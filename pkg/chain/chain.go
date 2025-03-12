// Package chain provides a way to chain multiple http.Handler together.
package chain

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/ipchecking"
)

// Status is a status that can be returned by a handler.
type Status struct {
	// Return is a flag that tells the chain to return. If Return is true, the
	// chain will return a 403 (e.g., the ip is in the denylist)
	Return bool
	// Break is a flag that tells the chain to break. If Break is true, the chain
	// will stop (e.g., the ip is in the allowlist)
	Break bool
}

// ChainHandler is a handler that can be chained.
type ChainHandler interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request) (*Status, error)
}

// Chain is a chain of handlers.
type Chain interface {
	ServeHTTP(w http.ResponseWriter, r *http.Request)
	WithStatus(status http.Handler)
	WithTrustedProxies(tp TrustedProxies) error
}

type TrustedProxies struct {
	IPs       []string          `yaml:"ips"`     // list of IPs to accept trusted headers from
	NetIPS    ipchecking.NetIPs `yaml:"-"`       // parsed IPs / CIDRs of trusted hosts
	IPHeaders []string          `yaml:"headers"` // list of headers to check (in order) for real IP. First populated header is used.
}

type chain struct {
	handlers       []ChainHandler
	final          http.Handler
	status         *http.Handler
	trustedProxies TrustedProxies
}

// New creates a new chain.
func New(final http.Handler, handlers ...ChainHandler) Chain {
	return &chain{
		handlers: handlers,
		final:    final,
	}
}

// WithStatus sets the status handler.
func (c *chain) WithStatus(status http.Handler) {
	c.status = &status
}

// WithTrustedProxies sets which IPs are allowed to set the headers.
//
//nolint:gofumpt //see https://github.com/golangci/golangci-lint/issues/1510 - gofumpt and wsl cannot agree how to format this function.
func (c *chain) WithTrustedProxies(tp TrustedProxies) error {
	var err error

	c.trustedProxies.IPHeaders = tp.IPHeaders
	c.trustedProxies.IPs = tp.IPHeaders
	c.trustedProxies.NetIPS, err = ipchecking.ParseNetIPs(tp.IPs)

	if err != nil {
		return fmt.Errorf("failed to parse trusted proxies: %w", err)
	}

	return nil
}

// ServeHTTP chains the handlers together, and calls the final handler at the end.
func (c *chain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP, err := c.getRemoteIP(r)
	if err != nil {
		log.Printf("chain.getRemoteIP error: %v", err)

		return
	}

	r, err = data.SetData(r, &remoteIP)
	if err != nil {
		log.Printf("data.SetData error: %v", err)

		return
	}

	for _, handler := range c.handlers {
		s, err := handler.ServeHTTP(w, r)
		if err != nil {
			log.Printf("handler.ServeHTTP error: %v", err)

			break
		}

		if s == nil {
			continue
		}

		if s.Return {
			w.WriteHeader(http.StatusForbidden)

			return
		}

		if s.Break {
			break
		}
	}

	if c.status != nil {
		(*c.status).ServeHTTP(w, r)

		return
	}

	c.final.ServeHTTP(w, r)
}

// getRemoteIP attempt to parse remote IP
// If TrustedProxies have been configured, that will be taken into account.
func (c *chain) getRemoteIP(r *http.Request) (data.Data, error) {
	var ret data.Data

	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		err = fmt.Errorf("failed to split remote address %q: %w", r.RemoteAddr, err)

		return ret, err
	}

	// is there a trusted header present?
	for _, th := range c.trustedProxies.IPHeaders {
		headerIP := r.Header.Get(th)

		if headerIP != "" && c.trustedProxies.NetIPS.Contains(remoteIP) { // target header is present, and IP is trusted
			ret.ViaTrustedProxy = remoteIP // remote IP was a trusted proxy
			ret.RemoteIP = headerIP        // and IP is defined by the header

			return ret, nil
		}
	}

	ret.RemoteIP = remoteIP

	return ret, nil
}
