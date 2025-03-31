// Package handler provides a fail2ban middleware.
// it provides an abstracting interface over different backends.
package handler

import (
	"errors"
	"net/http"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
)

// Fail2BanBackend interface that any fail2ban backend implements.
type Fail2BanBackend interface {
	// ShouldAllow check if the request should be allowed to proceed.
	// Called when a request was DENIED or otherwise failed a check.
	// increments the denied counter. Will return false if ban threshold has been reached.
	ShouldAllow(remoteIP string) (bool, error)

	// IsNotBanned Non-incrementing check to see if an IP is already banned.
	IsNotBanned(remoteIP string) (bool, error)
}

type handler struct {
	f2b Fail2BanBackend
}

// New creates a f2b Handler which checks if an IP is already banned, denying if so.
func New(f2b Fail2BanBackend) *handler {
	return &handler{f2b: f2b}
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) (*chain.Status, error) {
	data := data.GetData(req)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	inb, err := h.f2b.IsNotBanned(data.RemoteIP)

	if err != nil {
		return nil, err
	}

	if !inb {
		return &chain.Status{Return: true}, nil
	}

	return nil, nil
}
