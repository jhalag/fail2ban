// Package redis provides a stateless fail2ban implementation.
// it utilizes redis to store ban counters & state.
// bans will be retained between restarts of fail2ban.
package redis

import (
	"context"

	"github.com/redis/go-redis/v9"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
	"github.com/tomMoulard/fail2ban/pkg/rules"
)

// F2bRedis is a fail2ban implementation.
type F2bRedis struct {
	rules       rules.RulesTransformed
	IPs         map[string]ipchecking.IPViewed
	redisClient *redis.Client
}

// F2bRedisConfig is the config variables to pass to the redis client.
type F2bRedisConfig struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	DB       int    `yaml:"db"`
}

type redisRecord struct {
	IsBanned          bool `redis:"isbanned"`          // is currently banned
	BannedPermanently bool `redis:"bannedpermanently"` // is banned permanently. Should set IsBanned to true as well!
	BanImmune         bool `redis:"banimmune"`         // will never be banned
	FailCount         int  `redis:"failcount"`         // counter for failed requests
}

// redisKey generate a redis key string for a given IP.
func redisKey(ip string) string {
	return "fail2ban:addresses:" + ip
}

// New creates a new F2bRedis.
func New(rules rules.RulesTransformed, redisopt F2bRedisConfig) *F2bRedis {
	return &F2bRedis{
		rules: rules,
		redisClient: redis.NewClient(&redis.Options{
			Addr:     redisopt.Host,
			Password: redisopt.Password,
			DB:       redisopt.DB,
		}),
	}
}

// ShouldAllow check if the request should be allowed to proceed.
// Called when a request was DENIED or otherwise failed a check.
// increments the denied counter. Will return false if ban threshold has been reached.
func (u *F2bRedis) ShouldAllow(remoteIP string) (bool, error) {
	val := u.redisClient.HGetAll(context.Background(), redisKey(remoteIP))
	rec := redisRecord{}

	if err := val.Err(); err != nil {
		return false, err
	}

	// read in our variables from redis, if present
	if err := val.Scan(&rec); err != nil {
		return false, err
	}

	// increment the fail count
	{
		upd := u.redisClient.HIncrBy(context.Background(), redisKey(remoteIP), "failcount", 1) // increment the fail count
		if upd.Err() != nil {
			return false, upd.Err()
		}

		rec.FailCount++ // increment the local var as well
	}

	// if permanently banned, nothing more to do
	if rec.BannedPermanently {
		return false, nil
	}

	// if ban immune, nothing more to do
	if rec.BanImmune {
		return true, nil
	}

	// if not yet banned - is the count at the threshold?
	if rec.FailCount >= u.rules.MaxRetry {
		u.redisClient.Expire(context.Background(), redisKey(remoteIP), u.rules.Bantime) // use bantime for expiry of the key

		upd := u.redisClient.HSet(context.Background(), redisKey(remoteIP), "isbanned", true)

		return false, upd.Err()
	}

	// refresh hash expiry - if not banned, just findtime
	u.redisClient.Expire(context.Background(), redisKey(remoteIP), u.rules.Findtime)

	return true, nil
}

// IsNotBanned Non-incrementing check to see if an IP is already banned.
func (u *F2bRedis) IsNotBanned(remoteIP string) (bool, error) {
	val := u.redisClient.HGet(context.Background(), redisKey(remoteIP), "isbanned")

	if err := val.Err(); err != nil {
		return false, err
	}

	banstatus, err := val.Bool()
	if err != nil {
		return false, err
	}

	return banstatus, nil
}
