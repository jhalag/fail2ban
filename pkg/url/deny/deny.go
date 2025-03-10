// Package deny is a middleware that force denies requests from a list of IP addresses.
package deny

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
)

type deny struct {
	regs []*regexp.Regexp

	f2b fail2ban.Fail2Ban_interface
}

func New(regs []*regexp.Regexp, f2b fail2ban.Fail2Ban_interface) *deny {
	return &deny{
		regs: regs,
		f2b:  f2b,
	}
}

func (d *deny) ServeHTTP(w http.ResponseWriter, r *http.Request) (*chain.Status, error) {
	data := data.GetData(r)
	if data == nil {
		return nil, errors.New("failed to get data from request context")
	}

	fmt.Printf("data: %+v", data)

	for _, reg := range d.regs {
		if reg.MatchString(r.URL.String()) {
			d.f2b.ShouldAllow(data.RemoteIP) //increment failed counter

			fmt.Printf("Url (%q) was matched by regexpBan: %q", r.URL.String(), reg.String())

			return &chain.Status{Return: true}, nil
		}
	}

	return nil, nil
}
