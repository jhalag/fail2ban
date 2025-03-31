// Package fail2ban contains the Fail2ban mechanism for the plugin.
package fail2ban

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	f2bmemory "github.com/tomMoulard/fail2ban/pkg/backend/memory"
	f2bredis "github.com/tomMoulard/fail2ban/pkg/backend/redis"
	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/handler"
	lAllow "github.com/tomMoulard/fail2ban/pkg/list/allow"
	lDeny "github.com/tomMoulard/fail2ban/pkg/list/deny"
	"github.com/tomMoulard/fail2ban/pkg/response/status"
	"github.com/tomMoulard/fail2ban/pkg/rules"
	uAllow "github.com/tomMoulard/fail2ban/pkg/url/allow"
	uDeny "github.com/tomMoulard/fail2ban/pkg/url/deny"
)

func init() {
	log.SetOutput(os.Stdout)
}

// List struct.
type List struct {
	IP    []string
	Files []string
}

type Backend struct {
	Type  string                  `yaml:"type"`
	Redis f2bredis.F2bRedisConfig `yaml:"redis"`
}

// Config struct.
type Config struct {
	Denylist  List        `yaml:"denylist"`
	Allowlist List        `yaml:"allowlist"`
	Rules     rules.Rules `yaml:"port"`
	Backend   Backend     `yaml:"backend"`

	// deprecated
	Blacklist List `yaml:"blacklist"`
	// deprecated
	Whitelist List `yaml:"whitelist"`
}

// CreateConfig populates the Config data object.
func CreateConfig() *Config {
	return &Config{
		Rules: rules.Rules{
			Bantime:  "300s",
			Findtime: "120s",
			Enabled:  true,
		},
	}
}

// ImportIP extract all ip from config sources.
func ImportIP(list List) ([]string, error) {
	var rlist []string

	for _, ip := range list.Files {
		content, err := os.ReadFile(ip)
		if err != nil {
			return nil, fmt.Errorf("error when getting file content: %w", err)
		}

		rlist = append(rlist, strings.Split(string(content), "\n")...)
		if len(rlist) > 1 {
			rlist = rlist[:len(rlist)-1]
		}
	}

	rlist = append(rlist, list.IP...)

	return rlist, nil
}

// New instantiates and returns the required components used to handle a HTTP
// request.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	if !config.Rules.Enabled {
		log.Println("Plugin: FailToBan is disabled")

		return next, nil
	}

	allowIPs, err := ImportIP(config.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowlist IPs: %w", err)
	}

	if len(config.Whitelist.IP) > 0 || len(config.Whitelist.Files) > 0 {
		log.Println("Plugin: FailToBan: 'whitelist' is deprecated, please use 'allowlist' instead")

		whiteips, err := ImportIP(config.Whitelist)
		if err != nil {
			return nil, fmt.Errorf("failed to parse whitelist IPs: %w", err)
		}

		allowIPs = append(allowIPs, whiteips...)
	}

	allowHandler, err := lAllow.New(allowIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse whitelist IPs: %w", err)
	}

	denyIPs, err := ImportIP(config.Denylist)
	if err != nil {
		return nil, fmt.Errorf("failed to parse denylist IPs: %w", err)
	}

	if len(config.Blacklist.IP) > 0 || len(config.Blacklist.Files) > 0 {
		log.Println("Plugin: FailToBan: 'blacklist' is deprecated, please use 'denylist' instead")

		blackips, err := ImportIP(config.Blacklist)
		if err != nil {
			return nil, fmt.Errorf("failed to parse blacklist IPs: %w", err)
		}

		denyIPs = append(denyIPs, blackips...)
	}

	denyHandler, err := lDeny.New(denyIPs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse blacklist IPs: %w", err)
	}

	rules, err := rules.TransformRule(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("error when Transforming rules: %w", err)
	}

	var f2b handler.Fail2BanBackend

	switch config.Backend.Type {
	case "memory", "":
		f2b = f2bmemory.New(rules)
	case "redis":
		f2b = f2bredis.New(rules, config.Backend.Redis)
	default:
		log.Printf("Unknown backend handler specification [%s], defaulting to memory", config.Backend.Type)

		f2b = f2bmemory.New(rules)
	}

	log.Println("Plugin: FailToBan is up and running")

	c := chain.New(
		next,
		denyHandler,
		allowHandler,
		uDeny.New(rules.URLRegexpBan, f2b),
		uAllow.New(rules.URLRegexpAllow),
		handler.New(f2b),
	)

	if rules.StatusCode != "" {
		statusCodeHandler, err := status.New(next, rules.StatusCode, f2b)
		if err != nil {
			return nil, fmt.Errorf("failed to create status handler: %w", err)
		}

		c.WithStatus(statusCodeHandler)
	}

	return c, nil
}
