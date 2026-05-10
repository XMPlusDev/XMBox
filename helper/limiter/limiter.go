package limiter

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	redisStore "github.com/eko/gocache/store/redis/v4"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"

	"github.com/xmplusdev/xmbox/api"
)

var globalLimiter = New()

const (
	trafficUpPrefix   = "xmbox:traffic:up:"
	trafficDownPrefix = "xmbox:traffic:down:"
)

func trafficUpKey(email string) string   { return trafficUpPrefix + email }
func trafficDownKey(email string) string { return trafficDownPrefix + email }

type SubscriptionInfo struct {
	Id           int
	SpeedLimit   uint64
	IPLimit      int
	TrafficLimit int64 
	UsedTraffic  int64
}

type IPData struct {
	UID     int
	Tag     string
	UserTag string
}

// ── InboundInfo ───────────────────────────────────────────────────────────────
// TrafficUp / TrafficDown sync.Maps removed.
// All traffic delta I/O now goes through trafficRedis.

type InboundInfo struct {
	Tag             string
	NodeSpeedLimit  uint64
	SubscriptionInfo *sync.Map // key: email ("tag|uuid") → SubscriptionInfo
	BucketHub        *sync.Map // key: email → *rate.Limiter
	GlobalIPLimit   struct {
		config         *RedisConfig
		globalOnlineIP *marshaler.Marshaler
		redisClient    *redis.Client
	}
	trafficRedis  *redis.Client
	trafficExpiry time.Duration
}

type Limiter struct {
	InboundInfo *sync.Map
}

func New() *Limiter {
	return &Limiter{InboundInfo: new(sync.Map)}
}

func (l *Limiter) AddLimiter(tag string, expiry int, nodeSpeedLimit uint64, subscriptionList *[]api.SubscriptionInfo, redisConfig *RedisConfig) error {
	inboundInfo := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
		trafficExpiry:  time.Duration(expiry*2) * time.Second,
	}

	if redisConfig != nil && redisConfig.Enable {
		inboundInfo.GlobalIPLimit.config = redisConfig
		rc := redis.NewClient(&redis.Options{
			Network:  redisConfig.Network,
			Addr:     redisConfig.Addr,
			Username: redisConfig.Username,
			Password: redisConfig.Password,
			DB:       redisConfig.DB,
		})
		inboundInfo.GlobalIPLimit.redisClient = rc
		rs := redisStore.NewRedis(rc, store.WithExpiration(time.Duration(expiry)*time.Second))
		inboundInfo.GlobalIPLimit.globalOnlineIP = marshaler.New(cache.New[any](rs))
		inboundInfo.trafficRedis = rc
	} else {
		log.Printf("[limiter] warning: no Redis config for tag %s; traffic quota is per-node only", tag)
	}

	subscriptionMap := new(sync.Map)
	for _, u := range *subscriptionList {
		key := fmt.Sprintf("%s|%s|%d", tag, u.Email, u.Id)
		subscriptionMap.Store(key, SubscriptionInfo{
			Id:           u.Id,
			SpeedLimit:   u.SpeedLimit,
			IPLimit:      u.IPLimit,
			TrafficLimit: u.TrafficLimit,
			UsedTraffic:  u.UsedTraffic,
		})
	}
	inboundInfo.SubscriptionInfo = subscriptionMap
	l.InboundInfo.Store(tag, inboundInfo)
	return nil
}

func (l *Limiter) UpdateLimiter(tag string, updatedSubscriptionList *[]api.SubscriptionInfo) error {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return fmt.Errorf("no such limiter: %s found", tag)
	}
	inboundInfo := value.(*InboundInfo)

	for _, u := range *updatedSubscriptionList {
		key := fmt.Sprintf("%s|%s|%d", tag, u.Email, u.Id)
		inboundInfo.SubscriptionInfo.Store(key, SubscriptionInfo{
			Id:           u.Id,
			SpeedLimit:   u.SpeedLimit,
			IPLimit:      u.IPLimit,
			TrafficLimit: u.TrafficLimit,
			UsedTraffic:  u.UsedTraffic,
		})
		limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
		if limit > 0 {
			if bucket, ok := inboundInfo.BucketHub.Load(key); ok {
				lim := bucket.(*rate.Limiter)
				lim.SetLimit(rate.Limit(limit))
				lim.SetBurst(int(limit))
			}
		} else {
			inboundInfo.BucketHub.Delete(key)
		}
	}
	return nil
}

func (l *Limiter) DeleteLimiter(tag string) error {
	if v, ok := l.InboundInfo.Load(tag); ok {
		info := v.(*InboundInfo)
		if info.GlobalIPLimit.redisClient != nil {
			if err := info.GlobalIPLimit.redisClient.Close(); err != nil {
				log.Printf("error closing Redis client for tag %s: %v", tag, err)
			}
		}
		if info.trafficRedis != nil && info.trafficRedis != info.GlobalIPLimit.redisClient {
			info.trafficRedis.Close()
		}
	}
	l.InboundInfo.Delete(tag)
	return nil
}

func (l *Limiter) RemoveSubscriptions(tag string, emails []string) {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return
	}
	inboundInfo := value.(*InboundInfo)
	for _, email := range emails {
		inboundInfo.SubscriptionInfo.Delete(email)
		inboundInfo.BucketHub.Delete(email)
		if inboundInfo.trafficRedis != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			inboundInfo.trafficRedis.Del(ctx, trafficUpKey(email), trafficDownKey(email))
			cancel()
		}
	}
}

func (l *Limiter) CheckLimiter(tag, email, ip string) (*rate.Limiter, bool, bool, string) {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		log.Printf("Get Limiter information failed for tag: %s", tag)
		return nil, false, false, ""
	}

	inboundInfo := value.(*InboundInfo)

	var (
		speedLimit   uint64
		ipLimit      int
		uid          int
		trafficLimit int64
		usedTraffic  int64
	)
	if v, ok := inboundInfo.SubscriptionInfo.Load(email); ok {
		u := v.(SubscriptionInfo)
		uid = u.Id
		speedLimit = u.SpeedLimit
		ipLimit = u.IPLimit
		trafficLimit = u.TrafficLimit
		usedTraffic = u.UsedTraffic
	}

	if trafficLimit > 0 && inboundInfo.trafficRedis != nil {
		liveDelta := redisGetDelta(inboundInfo.trafficRedis, email)
		if usedTraffic+liveDelta >= trafficLimit {
			return nil, false, true, "Traffic limit exceeded"
		}
	}

	if inboundInfo.GlobalIPLimit.config != nil && inboundInfo.GlobalIPLimit.config.Enable {
		if checkLimit(inboundInfo, email, uid, ip, ipLimit, tag) {
			return nil, false, true, "IP limit exceeded"
		}
	}

	limit := determineRate(inboundInfo.NodeSpeedLimit, speedLimit)
	if limit == 0 {
		return nil, false, false, ""
	}
	if v, ok := inboundInfo.BucketHub.Load(email); ok {
		return v.(*rate.Limiter), true, false, ""
	}
	lim := rate.NewLimiter(rate.Limit(limit), int(limit))
	if v, loaded := inboundInfo.BucketHub.LoadOrStore(email, lim); loaded {
		return v.(*rate.Limiter), true, false, ""
	}
	return lim, true, false, ""
}

func (l *Limiter) AddDelta(tag, email string, upload, download int64) bool {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return false
	}
	inboundInfo := value.(*InboundInfo)

	subRaw, ok := inboundInfo.SubscriptionInfo.Load(email)
	if !ok {
		return false
	}
	sub := subRaw.(SubscriptionInfo)

	if inboundInfo.trafficRedis == nil {
		return false 
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	rc := inboundInfo.trafficRedis
	pipe := rc.Pipeline()

	var upCmd, downCmd *redis.IntCmd
	if upload > 0 {
		upCmd = pipe.IncrBy(ctx, trafficUpKey(email), upload)
		pipe.Expire(ctx, trafficUpKey(email), inboundInfo.trafficExpiry)
	}
	if download > 0 {
		downCmd = pipe.IncrBy(ctx, trafficDownKey(email), download)
		pipe.Expire(ctx, trafficDownKey(email), inboundInfo.trafficExpiry)
	}
	pipe.Exec(ctx)

	// Read back current values to check quota.
	var newUp, newDown int64
	if upCmd != nil {
		newUp, _ = upCmd.Result()
	} else {
		newUp, _ = rc.Get(ctx, trafficUpKey(email)).Int64()
	}
	if downCmd != nil {
		newDown, _ = downCmd.Result()
	} else {
		newDown, _ = rc.Get(ctx, trafficDownKey(email)).Int64()
	}

	if sub.TrafficLimit == 0 {
		return false
	}
	return sub.UsedTraffic+newUp+newDown >= sub.TrafficLimit
}

func (l *Limiter) DrainDeltas(tag string) []api.SubscriptionTraffic {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return nil
	}
	inboundInfo := value.(*InboundInfo)

	if inboundInfo.trafficRedis == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rc := inboundInfo.trafficRedis
	var result []api.SubscriptionTraffic

	inboundInfo.SubscriptionInfo.Range(func(k, v interface{}) bool {
		email := k.(string)
		sub := v.(SubscriptionInfo)

		upStr, errUp := rc.GetDel(ctx, trafficUpKey(email)).Result()
		downStr, errDown := rc.GetDel(ctx, trafficDownKey(email)).Result()

		var up, down int64
		if errUp == nil {
			up, _ = strconv.ParseInt(upStr, 10, 64)
		}
		if errDown == nil {
			down, _ = strconv.ParseInt(downStr, 10, 64)
		}
		if up == 0 && down == 0 {
			return true
		}
		result = append(result, api.SubscriptionTraffic{
			Id:       sub.Id,
			Upload:   up,
			Download: down,
		})
		return true
	})
	return result
}

func (l *Limiter) CheckTrafficExceeded(tag string) []string {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return nil
	}
	inboundInfo := value.(*InboundInfo)

	var exceeded []string
	inboundInfo.SubscriptionInfo.Range(func(k, v interface{}) bool {
		email := k.(string)
		sub := v.(SubscriptionInfo)
		if sub.TrafficLimit == 0 || inboundInfo.trafficRedis == nil {
			return true
		}
		liveDelta := redisGetDelta(inboundInfo.trafficRedis, email)
		if sub.UsedTraffic+liveDelta >= sub.TrafficLimit {
			exceeded = append(exceeded, email)
		}
		return true
	})
	return exceeded
}

func (l *Limiter) GetOnlineIPs(tag string) (*[]api.OnlineIP, error) {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return nil, fmt.Errorf("no such limiter: %s found", tag)
	}

	var onlineIP []api.OnlineIP
	inboundInfo := value.(*InboundInfo)

	if inboundInfo.GlobalIPLimit.config == nil || !inboundInfo.GlobalIPLimit.config.Enable {
		return &onlineIP, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()

	inboundInfo.BucketHub.Range(func(key, _ interface{}) bool {
		email := key.(string)
		v, ok := inboundInfo.SubscriptionInfo.Load(email)
		if !ok {
			return true
		}
		subscriptionInfo := v.(SubscriptionInfo)
		uniqueKey := strings.Replace(email, inboundInfo.Tag, strconv.Itoa(subscriptionInfo.IPLimit), 1)
		v2, err := inboundInfo.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string][]IPData))
		if err != nil {
			inboundInfo.BucketHub.Delete(email)
			return true
		}
		ipMap := v2.(*map[string][]IPData)
		for _, dataList := range *ipMap {
			for _, data := range dataList {
				if data.UserTag == email {
					return true
				}
			}
		}
		inboundInfo.BucketHub.Delete(email)
		return true
	})

	inboundInfo.SubscriptionInfo.Range(func(key, value interface{}) bool {
		email := key.(string)
		subscriptionInfo := value.(SubscriptionInfo)
		uniqueKey := strings.Replace(email, inboundInfo.Tag, strconv.Itoa(subscriptionInfo.IPLimit), 1)

		v, err := inboundInfo.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string][]IPData))
		if err != nil {
			return true
		}
		ipMap := v.(*map[string][]IPData)
		modified := false
		for ip, dataList := range *ipMap {
			remaining := make([]IPData, 0, len(dataList))
			for _, data := range dataList {
				if data.Tag == tag {
					onlineIP = append(onlineIP, api.OnlineIP{Id: data.UID, IP: ip})
					modified = true
				} else {
					remaining = append(remaining, data)
				}
			}
			(*ipMap)[ip] = remaining
		}
		if modified {
			go pushIP(inboundInfo, uniqueKey, ipMap)
		}
		return true
	})

	return &onlineIP, nil
}

func redisGetDelta(rc *redis.Client, email string) int64 {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pipe := rc.Pipeline()
	upCmd := pipe.Get(ctx, trafficUpKey(email))
	downCmd := pipe.Get(ctx, trafficDownKey(email))
	pipe.Exec(ctx)

	var up, down int64
	if v, err := upCmd.Int64(); err == nil {
		up = v
	}
	if v, err := downCmd.Int64(); err == nil {
		down = v
	}
	return up + down
}

func checkLimit(inboundInfo *InboundInfo, email string, uid int, ip string, ipLimit int, tag string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()

	uniqueKey := strings.Replace(email, inboundInfo.Tag, strconv.Itoa(ipLimit), 1)
	v, err := inboundInfo.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string][]IPData))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			go pushIP(inboundInfo, uniqueKey, &map[string][]IPData{ip: {{UID: uid, Tag: tag, UserTag: email}}})
		} else {
			log.Printf("cache service error for key %s: %v", uniqueKey, err)
		}
		return false
	}

	ipMap := v.(*map[string][]IPData)
	if dataList, ipExists := (*ipMap)[ip]; ipExists {
		found := false
		for i, data := range dataList {
			if data.UID == uid && data.Tag == tag {
				dataList[i] = IPData{UID: uid, Tag: tag, UserTag: email}
				found = true
				break
			}
		}
		if !found {
			(*ipMap)[ip] = append(dataList, IPData{UID: uid, Tag: tag, UserTag: email})
		} else {
			(*ipMap)[ip] = dataList
		}
		go pushIP(inboundInfo, uniqueKey, ipMap)
		return false
	}

	if ipLimit > 0 && len(*ipMap) >= ipLimit {
		return true
	}
	(*ipMap)[ip] = []IPData{{UID: uid, Tag: tag, UserTag: email}}
	go pushIP(inboundInfo, uniqueKey, ipMap)
	return false
}

func pushIP(inboundInfo *InboundInfo, uniqueKey string, ipMap *map[string][]IPData) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()
	if err := inboundInfo.GlobalIPLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap); err != nil {
		log.Printf("Redis cache set error for key %s: %v", uniqueKey, err)
	}
}

func determineRate(nodeLimit, subscriptionLimit uint64) uint64 {
	switch {
	case nodeLimit == 0 && subscriptionLimit == 0:
		return 0
	case nodeLimit == 0:
		return subscriptionLimit
	case subscriptionLimit == 0:
		return nodeLimit
	default:
		if nodeLimit < subscriptionLimit {
			return nodeLimit
		}
		return subscriptionLimit
	}
}

func GetLimiter(tag string) (*Limiter, error) {
	if _, ok := globalLimiter.InboundInfo.Load(tag); !ok {
		return nil, fmt.Errorf("no limiter found for inbound: %s", tag)
	}
	return globalLimiter, nil
}

func AddLimiter(tag string, expiry int, nodeSpeedLimit uint64, subscriptionList *[]api.SubscriptionInfo, redisConfig *RedisConfig) error {
	return globalLimiter.AddLimiter(tag, expiry, nodeSpeedLimit, subscriptionList, redisConfig)
}

func UpdateLimiter(tag string, updatedSubscriptionList *[]api.SubscriptionInfo) error {
	return globalLimiter.UpdateLimiter(tag, updatedSubscriptionList)
}

func DeleteLimiter(tag string) error {
	return globalLimiter.DeleteLimiter(tag)
}

func GetOnlineIPs(tag string) (*[]api.OnlineIP, error) {
	return globalLimiter.GetOnlineIPs(tag)
}

func RemoveSubscriptions(tag string, emails []string) {
	globalLimiter.RemoveSubscriptions(tag, emails)
}

func AddDelta(tag, email string, upload, download int64) bool {
	return globalLimiter.AddDelta(tag, email, upload, download)
}

func CheckTrafficExceeded(tag string) []string {
	return globalLimiter.CheckTrafficExceeded(tag)
}