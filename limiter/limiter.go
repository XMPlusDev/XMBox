package limiter

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

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

// ipKeyPrefix namespaces the per-subscription IP hashes.
//
// Shared verbatim with XMRay. ip_limit is a property of the subscription, not
// of whichever backend served the connection, so both must count into the same
// hash — otherwise a user reaches the limit separately on each and effectively
// gets twice the addresses. This relies on node tags being unique across both,
// which holds because each tag carries the panel's node ID.
//
// Also deliberately different from the key the previous format used: that one
// held a serialised map as a plain string, and a hash command against it would
// fail with WRONGTYPE. Old keys expire on their own TTL.
const ipKeyPrefix = "xmplus:ip:"

// ipKey returns the hash holding one subscription's connected addresses.
func ipKey(subscription string) string { return ipKeyPrefix + subscription }

// ipField identifies one address on one node. The tag is part of the field so a
// single address in use on two nodes stays distinguishable; "|" is a safe
// separator because neither IPv4 nor IPv6 literals contain it.
func ipField(ip, tag string) string { return ip + "|" + tag }

// ipLimitScript decides whether a connection is allowed and records it, in one
// atomic step.
//
// This replaces a read-modify-write of the whole address map: two connections
// for the same subscription would each read the map, add their own address and
// write the result back, so whichever finished last erased the other's entry.
// Running the check and the insert together inside Redis removes that window,
// and touching a single field rather than rewriting the map means concurrent
// connections no longer overwrite each other at all.
//
// KEYS[1] the subscription's hash. ARGV: 1 field, 2 UID, 3 IP limit (0 means
// unlimited), 4 TTL in seconds, 5 the address on its own.
// Returns 1 when the connection must be rejected, 0 when it is allowed.
var ipLimitScript = redis.NewScript(`
local field = ARGV[1]
if redis.call('HEXISTS', KEYS[1], field) == 0 then
  local limit = tonumber(ARGV[3])
  if limit > 0 then
    local seen = {}
    local distinct = 0
    for _, f in ipairs(redis.call('HKEYS', KEYS[1])) do
      local addr = string.match(f, '^(.+)|[^|]*$')
      if addr and not seen[addr] then
        seen[addr] = true
        distinct = distinct + 1
      end
    end
    -- An address already counted under another node must not be turned away:
    -- the limit is on distinct addresses, not on connections.
    if distinct >= limit and not seen[ARGV[5]] then
      return 1
    end
  end
end
redis.call('HSET', KEYS[1], field, ARGV[2])
redis.call('EXPIRE', KEYS[1], ARGV[4])
return 0
`)

// InboundInfo holds all limiter state for one inbound tag.
type InboundInfo struct {
	Tag              string
	NodeSpeedLimit   uint64
	IgnoreIPs        []string
	SubscriptionInfo *sync.Map // email → SubscriptionInfo
	BucketHub        *sync.Map // email → *rate.Limiter

	// IP limiting — populated only when Redis is enabled
	GlobalIPLimit struct {
		config *RedisConfig
		client *redis.Client
		expiry time.Duration
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
	timeout := cfg.timeout()
	rc := redis.NewClient(&redis.Options{
		Network:  cfg.Network,
		Addr:     cfg.Addr,
		Username: cfg.Username,
		Password: cfg.Password,
		DB:       cfg.DB,
		// Set explicitly rather than inheriting go-redis' CPU-derived default,
		// which is unrelated to how many connections this node accepts.
		PoolSize: cfg.poolSize(),
		// Fail a command that cannot get a pool slot in time instead of letting
		// it sit there until the caller's context expires.
		PoolTimeout:  timeout,
		ReadTimeout:  timeout,
		WriteTimeout: timeout,
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
func (l *Limiter) AddLimiter(tag string, expiry int, nodeSpeedLimit uint64, ignoreIPs []string, subscriptionList *[]api.SubscriptionInfo) error {
	info := &InboundInfo{
		Tag:            tag,
		NodeSpeedLimit: nodeSpeedLimit,
		IgnoreIPs:      ignoreIPs,
		BucketHub:      new(sync.Map),
	}

	if l.redisClient != nil {
		// Nodes share one Redis connection; the TTL is per node.
		info.GlobalIPLimit.config = l.redisConfig
		info.GlobalIPLimit.client = l.redisClient
		info.GlobalIPLimit.expiry = time.Duration(expiry) * time.Second
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

// UpdateNodeInfo refreshes node-level limiter settings (speed limit and
// ignore-IP list) in-place, without recreating subscription state or Redis
// wiring. Used when the node info changes but the inbound tag stays the same.
func (l *Limiter) UpdateNodeInfo(tag string, nodeSpeedLimit uint64, ignoreIPs []string) error {
	v, ok := l.InboundInfo.Load(tag)
	if !ok {
		return fmt.Errorf("no limiter found for tag %s", tag)
	}
	info := v.(*InboundInfo)
	info.NodeSpeedLimit = nodeSpeedLimit
	info.IgnoreIPs = ignoreIPs
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

	ignored := false
	for _, ignoreip := range info.IgnoreIPs {
		if ignoreip == ip {
			ignored = true
			break
		}
	}

	if !ignored && info.GlobalIPLimit.config != nil && info.GlobalIPLimit.config.Enable {
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

		// Result and Counters are appended in lockstep and must stay that way:
		// Chunk slices them by the same index so each batch carries the
		// counters for its own records. GetCounter uses LoadOrStore, so it
		// always returns storage.
		pending.Result = append(pending.Result, api.SubscriptionTraffic{
			Id:       sub.Id,
			Upload:   up,
			Download: down,
		})
		pending.Counters = append(pending.Counters, pendingCounter{
			storage: tc.GetCounter(email),
			up:      up,
			down:    down,
		})
		return true
	})

	if len(pending.Result) == 0 {
		return nil
	}
	return pending
}

// Add appends one record together with the counter it was drained from.
//
// DrainDeltas is the usual producer; this exists so a PendingTraffic can also
// be assembled directly, since the type is consumed outside this package.
func (p *PendingTraffic) Add(record api.SubscriptionTraffic, storage *counter.TrafficStorage, up, down int64) {
	p.Result = append(p.Result, record)
	p.Counters = append(p.Counters, pendingCounter{storage: storage, up: up, down: down})
}

// Chunk splits pending into batches of at most size records.
//
// Each batch keeps the counters belonging to its own records, so it can be
// reported and reset independently: one batch failing must neither discard
// counters another batch delivered nor retain ones it did not.
func (p *PendingTraffic) Chunk(size int) []*PendingTraffic {
	if p == nil || size <= 0 || len(p.Result) <= size {
		if p == nil || len(p.Result) == 0 {
			return nil
		}
		return []*PendingTraffic{p}
	}
	chunks := make([]*PendingTraffic, 0, (len(p.Result)+size-1)/size)
	for start := 0; start < len(p.Result); start += size {
		end := min(start+size, len(p.Result))
		chunks = append(chunks, &PendingTraffic{
			Result:   p.Result[start:end],
			Counters: p.Counters[start:end],
		})
	}
	return chunks
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

	ctx, cancel := context.WithTimeout(context.Background(), info.GlobalIPLimit.config.timeout())
	defer cancel()

	client := info.GlobalIPLimit.client

	// Drop rate buckets for subscriptions with nothing tracked any more. The
	// key's existence is the answer now, so no payload has to be fetched.
	info.BucketHub.Range(func(key, _ interface{}) bool {
		email := key.(string)
		if _, ok := info.SubscriptionInfo.Load(email); !ok {
			return true
		}
		n, err := client.Exists(ctx, ipKey(strings.TrimPrefix(email, tag+"_"))).Result()
		if err != nil || n == 0 {
			info.BucketHub.Delete(email)
		}
		return true
	})

	// Collect this tag's addresses and clear them.
	suffix := "|" + tag
	info.SubscriptionInfo.Range(func(key, _ interface{}) bool {
		email := key.(string)
		redisKey := ipKey(strings.TrimPrefix(email, tag+"_"))

		fields, err := client.HGetAll(ctx, redisKey).Result()
		if err != nil {
			log.Printf("[Limiter] failed to read online IPs for %s: %v", redisKey, err)
			return true
		}

		claimed := make([]string, 0, len(fields))
		for field, uid := range fields {
			if !strings.HasSuffix(field, suffix) {
				continue // another node's entry for the same subscription
			}
			id, convErr := strconv.Atoi(uid)
			if convErr != nil {
				continue
			}
			online = append(online, api.OnlineIP{Id: id, IP: strings.TrimSuffix(field, suffix)})
			claimed = append(claimed, field)
		}

		// Only the fields just read are deleted, so an address recorded between
		// the read and the delete stays to be reported next cycle rather than
		// being dropped unreported.
		if len(claimed) > 0 {
			if err := client.HDel(ctx, redisKey, claimed...).Err(); err != nil {
				log.Printf("[Limiter] failed to clear reported IPs for %s: %v", redisKey, err)
			}
		}
		return true
	})

	return &online, nil
}

// --- internal helpers ---

func checkIPLimit(info *InboundInfo, email string, uid int, ip string, ipLimit int, tag string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), info.GlobalIPLimit.config.timeout())
	defer cancel()

	key := ipKey(strings.TrimPrefix(email, info.Tag+"_"))
	ttl := int(info.GlobalIPLimit.expiry / time.Second)
	if ttl <= 0 {
		ttl = 1
	}

	rejected, err := ipLimitScript.Run(ctx, info.GlobalIPLimit.client,
		[]string{key}, ipField(ip, tag), uid, ipLimit, ttl, ip).Int()
	if err != nil {
		// Fail open. A Redis problem locking every user out of every node is a
		// far worse outcome than briefly not enforcing the address limit.
		log.Printf("[Limiter] IP limit check failed for %s: %v", key, err)
		return false
	}
	return rejected == 1
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

func AddLimiter(tag string, expiry int, nodeSpeedLimit uint64, ignoreIPs []string, subscriptionList *[]api.SubscriptionInfo) error {
	return globalLimiter.AddLimiter(tag, expiry, nodeSpeedLimit, ignoreIPs, subscriptionList)
}

func UpdateLimiter(tag string, updated *[]api.SubscriptionInfo) error {
	return globalLimiter.UpdateLimiter(tag, updated)
}

func UpdateNodeInfo(tag string, nodeSpeedLimit uint64, ignoreIPs []string) error {
	return globalLimiter.UpdateNodeInfo(tag, nodeSpeedLimit, ignoreIPs)
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
