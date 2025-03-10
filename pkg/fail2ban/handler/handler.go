// Package handler provides a fail2ban middleware.
package handler

import (
	"errors"
	"net/http"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
)

type handler struct {
	f2b fail2ban.Fail2Ban_interface
}

// f2b Handler to check if an IP is already banned, denying if so.
func New(f2b fail2ban.Fail2Ban_interface) *handler {
	return &handler{f2b: f2b}
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) (*chain.Status, error) {
	data := data.GetData(req)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	if !h.f2b.IsNotBanned(data.RemoteIP) {
		return &chain.Status{Return: true}, nil
	}

	return nil, nil
}
