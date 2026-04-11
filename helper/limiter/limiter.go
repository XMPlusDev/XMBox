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

type SubscriptionInfo struct {
	Id         int
	UUID       string
	Email      string
	SpeedLimit uint64
	IPLimit    int
}

type IPData struct {
	UID     int
	Tag     string
	UserTag string
}

type InboundInfo struct {
	Tag             string
	NodeSpeedLimit  uint64
	SubscriptionInfo *sync.Map
	BucketHub       *sync.Map
	GlobalIPLimit   struct {
		config         *RedisConfig
		globalOnlineIP *marshaler.Marshaler
		redisClient    *redis.Client
	}
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
	}

	subscriptionMap := new(sync.Map)
	for _, u := range *subscriptionList {
		subscriptionMap.Store(fmt.Sprintf("%s|%s", tag, u.UUID), SubscriptionInfo{
			Id:         u.Id,
			UUID:       u.UUID,
			Email:      u.Email,
			SpeedLimit: u.SpeedLimit,
			IPLimit:    u.IPLimit,
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
		userTag := fmt.Sprintf("%s|%s", tag, u.UUID)
		inboundInfo.SubscriptionInfo.Store(userTag, SubscriptionInfo{
			Id:         u.Id,
			UUID:       u.UUID,
			Email:      u.Email,
			SpeedLimit: u.SpeedLimit,
			IPLimit:    u.IPLimit,
		})

		limit := determineRate(inboundInfo.NodeSpeedLimit, u.SpeedLimit)
		if limit > 0 {
			if bucket, ok := inboundInfo.BucketHub.Load(userTag); ok {
				lim := bucket.(*rate.Limiter)
				lim.SetLimit(rate.Limit(limit))
				lim.SetBurst(int(limit))
			}
		} else {
			inboundInfo.BucketHub.Delete(userTag)
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
	}
	l.InboundInfo.Delete(tag)
	return nil
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
		userTag := key.(string)
		v, ok := inboundInfo.SubscriptionInfo.Load(userTag)
		if !ok {
			return true
		}
		subscriptionInfo := v.(SubscriptionInfo)
		uniqueKey := strings.Replace(userTag, inboundInfo.Tag, strconv.Itoa(subscriptionInfo.IPLimit), 1)

		v2, err := inboundInfo.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string][]IPData))
		if err != nil {
			inboundInfo.BucketHub.Delete(userTag)
			return true
		}

		ipMap := v2.(*map[string][]IPData)
		for _, dataList := range *ipMap {
			for _, data := range dataList {
				if data.UserTag == userTag {
					return true
				}
			}
		}
		inboundInfo.BucketHub.Delete(userTag)
		return true
	})

	inboundInfo.SubscriptionInfo.Range(func(key, value interface{}) bool {
		userTag := key.(string)
		subscriptionInfo := value.(SubscriptionInfo)
		uniqueKey := strings.Replace(userTag, inboundInfo.Tag, strconv.Itoa(subscriptionInfo.IPLimit), 1)

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

func (l *Limiter) CheckLimiter(tag, uuid, ip string) (*rate.Limiter, bool, bool, string) {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		log.Printf("Get Limiter information failed for tag: %s", tag)
		return nil, false, false, ""
	}

	inboundInfo := value.(*InboundInfo)
	userTag := fmt.Sprintf("%s|%s", tag, uuid)

	var (
		speedLimit uint64
		ipLimit    int
		uid        int
		email      string
	)
	if v, ok := inboundInfo.SubscriptionInfo.Load(userTag); ok {
		u := v.(SubscriptionInfo)
		uid = u.Id
		email = u.Email
		speedLimit = u.SpeedLimit
		ipLimit = u.IPLimit
	}

	if inboundInfo.GlobalIPLimit.config != nil && inboundInfo.GlobalIPLimit.config.Enable {
		if checkLimit(inboundInfo, userTag, uid, ip, ipLimit, tag) {
			return nil, false, true, email
		}
	}

	limit := determineRate(inboundInfo.NodeSpeedLimit, speedLimit)
	if limit == 0 {
		return nil, false, false, email
	}

	if v, ok := inboundInfo.BucketHub.Load(userTag); ok {
		return v.(*rate.Limiter), true, false, email
	}
	lim := rate.NewLimiter(rate.Limit(limit), int(limit))
	if v, loaded := inboundInfo.BucketHub.LoadOrStore(userTag, lim); loaded {
		return v.(*rate.Limiter), true, false, email
	}
	return lim, true, false, email
}

func checkLimit(inboundInfo *InboundInfo, userTag string, uid int, ip string, ipLimit int, tag string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(inboundInfo.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()

	uniqueKey := strings.Replace(userTag, inboundInfo.Tag, strconv.Itoa(ipLimit), 1)

	v, err := inboundInfo.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string][]IPData))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			go pushIP(inboundInfo, uniqueKey, &map[string][]IPData{ip: {{UID: uid, Tag: tag, UserTag: userTag}}})
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
				dataList[i] = IPData{UID: uid, Tag: tag, UserTag: userTag}
				found = true
				break
			}
		}
		if !found {
			(*ipMap)[ip] = append(dataList, IPData{UID: uid, Tag: tag, UserTag: userTag})
		} else {
			(*ipMap)[ip] = dataList
		}
		go pushIP(inboundInfo, uniqueKey, ipMap)
		return false
	}

	if ipLimit > 0 && len(*ipMap) >= ipLimit {
		return true
	}

	(*ipMap)[ip] = []IPData{{UID: uid, Tag: tag, UserTag: userTag}}
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

func (l *Limiter) RemoveSubscriptions(tag string, uuids []string) {
	value, ok := l.InboundInfo.Load(tag)
	if !ok {
		return
	}
	inboundInfo := value.(*InboundInfo)
	for _, uuid := range uuids {
		userTag := fmt.Sprintf("%s|%s", tag, uuid)
		inboundInfo.SubscriptionInfo.Delete(userTag)
		inboundInfo.BucketHub.Delete(userTag)
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

func RemoveSubscriptions(tag string, uuids []string) {
	globalLimiter.RemoveSubscriptions(tag, uuids)
}