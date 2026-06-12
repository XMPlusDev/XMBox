package limiter

import (
	"context"
	"fmt"
	"log"
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
	"github.com/xmplusdev/xmbox/counter"
)

// globalLimiter is the single Limiter instance shared across all nodes.
var globalLimiter = New()

// SubscriptionInfo holds per-user limits stored in the limiter.
type SubscriptionInfo struct {
	Id         int
	SpeedLimit uint64
	IPLimit    int
}

// IPData is the record stored in Redis per connected IP.
type IPData struct {
	UID     int
	Tag     string
	UserTag string // full email key: "<tag>_<email>"
}

// InboundInfo holds all limiter state for one inbound tag.
type InboundInfo struct {
	Tag             string
	NodeSpeedLimit  uint64
	SubscriptionInfo *sync.Map // email → SubscriptionInfo
	BucketHub        *sync.Map // email → *rate.Limiter

	// IP limiting — populated only when Redis is enabled
	GlobalIPLimit struct {
		config         *RedisConfig
		globalOnlineIP *marshaler.Marshaler
	}
}

// Limiter is the top-level rate/IP limiter.  It is initialised once with a
// shared Redis client (if enabled) and then used by every node.
type Limiter struct {
	InboundInfo *sync.Map

	// Shared Redis client — set once by Init(), never changed afterwards.
	redisConfig *RedisConfig
	redisClient *redis.Client
}

// New creates an uninitialised Limiter (no Redis).
func New() *Limiter { return &Limiter{InboundInfo: new(sync.Map)} }

// Init wires the global limiter to a single Redis client derived from config.
// Must be called once at process startup before any AddLimiter calls.
func Init(cfg *RedisConfig) error {
	if cfg == nil || !cfg.Enable {
		return nil
	}
	rc := redis.NewClient(&redis.Options{
		Network:  cfg.Network,
		Addr:     cfg.Addr,
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rc.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("limiter: Redis ping failed: %w", err)
	}
	globalLimiter.redisConfig = cfg
	globalLimiter.redisClient = rc
	log.Printf("[Limiter] Redis initialised at %s", cfg.Addr)
	return nil
}

// AddLimiter registers a new inbound tag with the global limiter.
// expiry is the IP-map TTL in seconds (usually equal to node UpdateInterval).
func (l *Limiter) AddLimiter(tag string, expiry int, nodeSpeedLimit uint64, subscriptionList *[]api.SubscriptionInfo) error {
	info := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		BucketHub:      new(sync.Map),
	}

	if l.redisClient != nil {
		// Each node gets its own marshaler (with its own TTL) but shares the
		// underlying Redis connection.
		info.GlobalIPLimit.config = l.redisConfig
		rs := redisStore.NewRedis(l.redisClient, store.WithExpiration(time.Duration(expiry)*time.Second))
		info.GlobalIPLimit.globalOnlineIP = marshaler.New(cache.New[any](rs))
	} else {
		log.Printf("[Limiter] Redis disabled — IP limiting inactive for tag %s", tag)
	}

	subMap := new(sync.Map)
	for _, u := range *subscriptionList {
		subMap.Store(emailKey(tag, u.Email), SubscriptionInfo{
			Id:         u.Id,
			SpeedLimit: u.SpeedLimit,
			IPLimit:    u.IPLimit,
		})
	}
	info.SubscriptionInfo = subMap

	l.InboundInfo.Store(tag, info)
	return nil
}

// UpdateLimiter updates existing subscription limits in-place (no Redis recreation).
func (l *Limiter) UpdateLimiter(tag string, updatedList *[]api.SubscriptionInfo) error {
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		return fmt.Errorf("no limiter found for tag %s", tag)
	}
	info := v.(*InboundInfo)

	for _, u := range *updatedList {
		key := emailKey(tag, u.Email)
		info.SubscriptionInfo.Store(key, SubscriptionInfo{
			Id:         u.Id,
			SpeedLimit: u.SpeedLimit,
			IPLimit:    u.IPLimit,
		})
		limit := determineRate(info.NodeSpeedLimit, u.SpeedLimit)
		if limit > 0 {
			if bucket, ok := info.BucketHub.Load(key); ok {
				lim := bucket.(*rate.Limiter)
				lim.SetLimit(rate.Limit(limit))
				lim.SetBurst(int(limit))
			}
		} else {
			info.BucketHub.Delete(key)
		}
	}
	return nil
}

// DeleteLimiter removes an inbound tag from the limiter.
// The shared Redis client is NOT closed here.
func (l *Limiter) DeleteLimiter(tag string) error {
	l.InboundInfo.Delete(tag)
	return nil
}

// RemoveSubscriptions removes specific email keys from an inbound's maps.
func (l *Limiter) RemoveSubscriptions(tag string, emails []string) {
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		return
	}
	info := v.(*InboundInfo)
	for _, email := range emails {
		info.SubscriptionInfo.Delete(email)
		info.BucketHub.Delete(email)
	}
}

// CheckLimiter checks rate and IP limits for a connection.
// Returns (bucket, isRateLimited, reject, reason).
func (l *Limiter) CheckLimiter(tag, email, ip string) (*rate.Limiter, bool, bool, string) {
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		log.Printf("[Limiter] no info for tag: %s", tag)
		return nil, false, false, ""
	}
	info := v.(*InboundInfo)

	var uid int
	var speedLimit uint64
	var ipLimit int

	if sv, ok := info.SubscriptionInfo.Load(email); ok {
		sub := sv.(SubscriptionInfo)
		uid = sub.Id
		speedLimit = sub.SpeedLimit
		ipLimit = sub.IPLimit
	}

	if info.GlobalIPLimit.config != nil && info.GlobalIPLimit.config.Enable {
		if checkIPLimit(info, email, uid, ip, ipLimit, tag) {
			return nil, false, true, "IP limit exceeded"
		}
	}

	limit := determineRate(info.NodeSpeedLimit, speedLimit)
	if limit > 0 {
		lim := rate.NewLimiter(rate.Limit(limit), int(limit))
		if existing, loaded := info.BucketHub.LoadOrStore(email, lim); loaded {
			return existing.(*rate.Limiter), true, false, ""
		}
		return lim, true, false, ""
	}
	return nil, false, false, ""
}

// PendingTraffic bundles the data needed to report and then reset traffic.
type PendingTraffic struct {
	Result   []api.SubscriptionTraffic
	Counters []pendingCounter
}

type pendingCounter struct {
	storage *counter.TrafficStorage
	up      int64
	down    int64
}

// DrainDeltas reads accumulated traffic counters for all subscriptions.
func (l *Limiter) DrainDeltas(tag string, tc *counter.TrafficCounter) *PendingTraffic {
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		return nil
	}
	info := v.(*InboundInfo)
	pending := &PendingTraffic{}

	info.SubscriptionInfo.Range(func(k, val interface{}) bool {
		email := k.(string)
		sub := val.(SubscriptionInfo)

		up := tc.GetUpCount(email)
		down := tc.GetDownCount(email)
		if up == 0 && down == 0 {
			return true
		}

		pending.Result = append(pending.Result, api.SubscriptionTraffic{
			Id:       sub.Id,
			Upload:   up,
			Download: down,
		})
		if s := tc.GetCounter(email); s != nil {
			pending.Counters = append(pending.Counters, pendingCounter{
				storage: s,
				up:      up,
				down:    down,
			})
		}
		return true
	})

	if len(pending.Result) == 0 {
		return nil
	}
	return pending
}

// ResetTraffic subtracts the reported amounts from the in-memory counters.
func (l *Limiter) ResetTraffic(pending *PendingTraffic) {
	if pending == nil {
		return
	}
	for _, pc := range pending.Counters {
		pc.storage.UpCounter.Add(-pc.up)
		pc.storage.DownCounter.Add(-pc.down)
	}
}

// GetOnlineIPs returns currently connected IPs for all subscriptions under tag,
// clearing this tag's entries from Redis afterwards.
func (l *Limiter) GetOnlineIPs(tag string) (*[]api.OnlineIP, error) {
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		return nil, fmt.Errorf("no limiter for tag: %s", tag)
	}
	info := v.(*InboundInfo)

	var online []api.OnlineIP

	if info.GlobalIPLimit.config == nil || !info.GlobalIPLimit.config.Enable {
		return &online, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()

	// Clean up stale bucket entries
	info.BucketHub.Range(func(key, _ interface{}) bool {
		email := key.(string)
		if _, ok := info.SubscriptionInfo.Load(email); !ok {
			return true
		}
		uniqueKey := strings.TrimPrefix(email, tag+"_")
		v2, err := info.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string][]IPData))
		if err != nil {
			info.BucketHub.Delete(email)
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
		info.BucketHub.Delete(email)
		return true
	})

	// Collect IPs for this tag and clear them
	info.SubscriptionInfo.Range(func(key, _ interface{}) bool {
		email := key.(string)
		uniqueKey := strings.TrimPrefix(email, tag+"_")

		v2, err := info.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string][]IPData))
		if err != nil {
			return true
		}
		ipMap := v2.(*map[string][]IPData)
		modified := false
		for ip, dataList := range *ipMap {
			remaining := make([]IPData, 0, len(dataList))
			for _, d := range dataList {
				if d.Tag == tag {
					online = append(online, api.OnlineIP{Id: d.UID, IP: ip})
					modified = true
				} else {
					remaining = append(remaining, d)
				}
			}
			(*ipMap)[ip] = remaining
		}
		if modified {
			go pushIP(info, uniqueKey, ipMap)
		}
		return true
	})

	return &online, nil
}

// --- internal helpers ---

func checkIPLimit(info *InboundInfo, email string, uid int, ip string, ipLimit int, tag string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()

	uniqueKey := strings.TrimPrefix(email, info.Tag+"_")
	v, err := info.GlobalIPLimit.globalOnlineIP.Get(ctx, uniqueKey, new(map[string][]IPData))
	if err != nil {
		if _, ok := err.(*store.NotFound); ok {
			go pushIP(info, uniqueKey, &map[string][]IPData{ip: {{UID: uid, Tag: tag, UserTag: email}}})
		} else {
			log.Printf("[Limiter] cache error for key %s: %v", uniqueKey, err)
		}
		return false
	}

	ipMap := v.(*map[string][]IPData)
	if dataList, exists := (*ipMap)[ip]; exists {
		found := false
		for i, d := range dataList {
			if d.UID == uid && d.Tag == tag {
				dataList[i] = IPData{UID: uid, Tag: tag, UserTag: email}
				found = true
				break
			}
		}
		if !found {
			(*ipMap)[ip] = append(dataList, IPData{UID: uid, Tag: tag, UserTag: email})
		}
		go pushIP(info, uniqueKey, ipMap)
		return false
	}

	if ipLimit > 0 && len(*ipMap) >= ipLimit {
		return true
	}
	(*ipMap)[ip] = []IPData{{UID: uid, Tag: tag, UserTag: email}}
	go pushIP(info, uniqueKey, ipMap)
	return false
}

func pushIP(info *InboundInfo, uniqueKey string, ipMap *map[string][]IPData) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(info.GlobalIPLimit.config.Timeout)*time.Second)
	defer cancel()
	if err := info.GlobalIPLimit.globalOnlineIP.Set(ctx, uniqueKey, ipMap); err != nil {
		log.Printf("[Limiter] Redis set error for key %s: %v", uniqueKey, err)
	}
}

func determineRate(nodeLimit, subLimit uint64) uint64 {
	switch {
	case nodeLimit == 0 && subLimit == 0:
		return 0
	case nodeLimit == 0:
		return subLimit
	case subLimit == 0:
		return nodeLimit
	default:
		if nodeLimit < subLimit {
			return nodeLimit
		}
		return subLimit
	}
}

func emailKey(tag, email string) string {
	return tag + "_" + email
}

// --- Package-level convenience wrappers that forward to globalLimiter ---

func GetLimiter(tag string) (*Limiter, error) {
	if _, ok := globalLimiter.InboundInfo.Load(tag); !ok {
		return nil, fmt.Errorf("no limiter for inbound: %s", tag)
	}
	return globalLimiter, nil
}

func AddLimiter(tag string, expiry int, nodeSpeedLimit uint64, subscriptionList *[]api.SubscriptionInfo) error {
	return globalLimiter.AddLimiter(tag, expiry, nodeSpeedLimit, subscriptionList)
}

func UpdateLimiter(tag string, updated *[]api.SubscriptionInfo) error {
	return globalLimiter.UpdateLimiter(tag, updated)
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

func DrainDeltas(tag string, tc *counter.TrafficCounter) *PendingTraffic {
	return globalLimiter.DrainDeltas(tag, tc)
}

func ResetTraffic(pending *PendingTraffic) {
	globalLimiter.ResetTraffic(pending)
}
