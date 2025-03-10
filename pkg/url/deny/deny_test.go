package deny

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/pkg/chain"
	"github.com/tomMoulard/fail2ban/pkg/data"
	"github.com/tomMoulard/fail2ban/pkg/fail2ban"
)

// deny is a standalone part of a chain. we only need to test
// if it returns the proper Chain.Status. Other aspects of functionality
// (e.g. fail counting, bans) are tested separately.
func TestDeny(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		url          string
		regs         []*regexp.Regexp
		denyExpected bool
	}{
		{
			name:         "non-matched request. Grant",
			url:          "https://example.com/",
			regs:         []*regexp.Regexp{regexp.MustCompile(`^https://example.com/foo$`)},
			denyExpected: false,
		},
		{
			name:         "matched request. Deny",
			url:          "https://example.com/foo",
			regs:         []*regexp.Regexp{regexp.MustCompile(`^https://example.com/foo$`)},
			denyExpected: true,
		},
		{
			name: "matched request. Deny. (multiple regex)",
			url:  "https://example.com/bar",
			regs: []*regexp.Regexp{
				regexp.MustCompile(`^https://example.com/foo$`),
				regexp.MustCompile(`^https://example.com/bar$`),
				regexp.MustCompile(`^https://example.com/baz$`),
			},
			denyExpected: true,
		},
		{
			name: "non-matched request. Grant. (multiple regex)",
			url:  "https://example.com/banana",
			regs: []*regexp.Regexp{
				regexp.MustCompile(`^https://example.com/foo$`),
				regexp.MustCompile(`^https://example.com/bar$`),
				regexp.MustCompile(`^https://example.com/baz$`),
			},
			denyExpected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			d := New(test.regs, &fail2ban.Fail2BanDummy{}) // deny instance to test

			req := httptest.NewRequest(http.MethodGet, test.url, nil)

			recorder := &httptest.ResponseRecorder{}
			req, err := data.ServeHTTP(recorder, req) // populate the context data flag
			require.NoError(t, err)

			resp, err := d.ServeHTTP(recorder, req)

			if resp == nil { // if we did not get a chain.Status object, populate a blank one.
				resp = &chain.Status{}
			}

			require.NoError(t, err)
			require.Equal(t, resp.Return, test.denyExpected)
		})
	}
}
