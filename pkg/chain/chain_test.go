package chain

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tomMoulard/fail2ban/pkg/data"
)

type mockHandler struct {
	called         int
	err            error
	expectedCalled int
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.called++
}

func (m *mockHandler) assert(t *testing.T) {
	t.Helper()

	assert.Equal(t, m.expectedCalled, m.called)
}

type mockChainHandler struct {
	mockHandler
	status *Status
}

func (m *mockChainHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (*Status, error) {
	m.called++

	return m.status, m.err
}

func (m *mockChainHandler) assert(t *testing.T) {
	t.Helper()

	assert.Equal(t, m.expectedCalled, m.called)
}

func TestChain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		finalHandler     *mockHandler
		handlers         []ChainHandler
		expectedStatus   *Status
		expectFinalCount int
	}{
		{
			name:         "return",
			finalHandler: &mockHandler{expectedCalled: 0},
			handlers: []ChainHandler{&mockChainHandler{
				status:      &Status{Return: true},
				mockHandler: mockHandler{expectedCalled: 1},
			}},
			expectedStatus: &Status{
				Return: true,
			},
		},
		{
			name:         "break",
			finalHandler: &mockHandler{expectedCalled: 1},
			handlers: []ChainHandler{&mockChainHandler{
				status:      &Status{Break: true},
				mockHandler: mockHandler{expectedCalled: 1},
			}},
			expectedStatus: &Status{
				Break: true,
			},
		},
		{
			name:         "nil",
			finalHandler: &mockHandler{expectedCalled: 1},
			handlers: []ChainHandler{&mockChainHandler{
				status:      nil,
				mockHandler: mockHandler{expectedCalled: 1},
			}},
		},
		{
			name:         "error",
			finalHandler: &mockHandler{expectedCalled: 1},
			handlers: []ChainHandler{&mockChainHandler{
				mockHandler: mockHandler{
					err:            errors.New("error"),
					expectedCalled: 1,
				},
			}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c := New(test.finalHandler, test.handlers...)
			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)

			c.ServeHTTP(recorder, req)

			test.finalHandler.assert(t)

			for _, handler := range test.handlers {
				mch, ok := handler.(*mockChainHandler)
				require.True(t, ok)
				mch.assert(t)
			}
		})
	}
}

type mockChainOrderHandler struct {
	status int
}

var countOrder int

func (m *mockChainOrderHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (*Status, error) {
	m.status = countOrder
	countOrder++

	return nil, nil
}

func TestChainOrder(t *testing.T) {
	t.Parallel()

	a := &mockChainOrderHandler{}
	b := &mockChainOrderHandler{}
	c := &mockChainOrderHandler{}
	final := &mockHandler{
		expectedCalled: 1,
	}

	ch := New(final, a, b, c)
	r := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	ch.ServeHTTP(nil, r)

	assert.Equal(t, 0, a.status)
	assert.Equal(t, 1, b.status)
	assert.Equal(t, 2, c.status)
	final.assert(t)
}

type mockDataHandler struct {
	t          *testing.T
	ExpectData *data.Data
}

func (m *mockDataHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) (*Status, error) {
	d := data.GetData(r)
	assert.Equal(m.t, m.ExpectData, d)

	return nil, nil
}

func TestChainRequestContext(t *testing.T) {
	t.Parallel()

	handler := &mockDataHandler{
		t:          t,
		ExpectData: &data.Data{RemoteIP: "192.0.2.1"},
	}

	final := &mockHandler{
		expectedCalled: 1,
	}

	ch := New(final, handler)
	r := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	ch.ServeHTTP(nil, r)

	final.assert(t)
}

func TestChainWithStatus(t *testing.T) {
	t.Parallel()

	handler := &mockChainHandler{
		mockHandler: mockHandler{expectedCalled: 1},
	}
	final := &mockHandler{expectedCalled: 0}
	status := &mockHandler{expectedCalled: 1}

	ch := New(final, handler)
	ch.WithStatus(status)

	r := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
	ch.ServeHTTP(nil, r)

	handler.assert(t)
	final.assert(t)
	status.assert(t)
}

func TestChainBadIP(t *testing.T) {
	t.Parallel()

	hstub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	})
	c := New(hstub)

	err := c.WithTrustedProxies(TrustedProxies{IPs: []string{"1.2.3.foobar"}})
	assert.Error(t, err)
}

func TestChainTrustedIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		remoteAddr     string
		expectedData   data.Data
		headers        map[string]string
		trustedProxies TrustedProxies
	}{
		{
			name:       "Basic request",
			remoteAddr: "1.2.3.4:12345",
			expectedData: data.Data{
				RemoteIP: "1.2.3.4",
			},
		},
		{
			name:       "Trusted header, untrusted proxy",
			remoteAddr: "1.2.3.4:12345",
			expectedData: data.Data{
				RemoteIP: "1.2.3.4",
			},
			headers: map[string]string{"CF-Connecting-IP": "4.3.2.1"},
			trustedProxies: TrustedProxies{
				IPs:       []string{"7.8.9.10"},
				IPHeaders: []string{"CF-Connecting-IP"},
			},
		},
		{
			name:       "Trusted header, trusted proxy",
			remoteAddr: "7.8.9.10:12345",
			expectedData: data.Data{
				RemoteIP:        "4.3.2.1",
				ViaTrustedProxy: "7.8.9.10",
			},
			headers: map[string]string{"CF-Connecting-IP": "4.3.2.1"},
			trustedProxies: TrustedProxies{
				IPs:       []string{"7.8.9.10"},
				IPHeaders: []string{"CF-Connecting-IP"},
			},
		},
		{
			name:       "Trusted proxy, no header present",
			remoteAddr: "7.8.9.10:12345",
			expectedData: data.Data{
				RemoteIP: "7.8.9.10",
			},
			trustedProxies: TrustedProxies{
				IPs:       []string{"7.8.9.10"},
				IPHeaders: []string{"CF-Connecting-IP"},
			},
		},
		{
			name:       "trusted proxies, other connection",
			remoteAddr: "11.12.13.14:12345",
			expectedData: data.Data{
				RemoteIP: "11.12.13.14",
			},
			trustedProxies: TrustedProxies{
				IPs:       []string{"7.8.9.10", "7.8.9.115"},
				IPHeaders: []string{"CF-Connecting-IP"},
			},
		},
		{
			name:       "multiple trusted proxies",
			remoteAddr: "7.8.9.116:12345",
			expectedData: data.Data{
				RemoteIP:        "4.3.2.100",
				ViaTrustedProxy: "7.8.9.116",
			},
			headers: map[string]string{"CF-Connecting-IP": "4.3.2.100"},
			trustedProxies: TrustedProxies{
				IPs:       []string{"7.8.9.10", "7.8.9.115", "7.8.9.116", "7.8.9.117"},
				IPHeaders: []string{"CF-Connecting-IP"},
			},
		},
		{
			name:       "multiple trusted proxies, by CIDR",
			remoteAddr: "7.8.9.116:12345",
			expectedData: data.Data{
				RemoteIP:        "4.3.2.100",
				ViaTrustedProxy: "7.8.9.116",
			},
			headers: map[string]string{"CF-Connecting-IP": "4.3.2.100"},
			trustedProxies: TrustedProxies{
				IPs:       []string{"7.8.9.0/24", "7.8.50.0/24"},
				IPHeaders: []string{"CF-Connecting-IP"},
			},
		},
		{
			name:       "multiple trusted proxies, by CIDR - none applicable",
			remoteAddr: "7.66.9.116:12345",
			expectedData: data.Data{
				RemoteIP: "7.66.9.116",
			},
			headers: map[string]string{"CF-Connecting-IP": "4.3.2.100"},
			trustedProxies: TrustedProxies{
				IPs:       []string{"7.8.9.0/24", "7.8.50.0/24"},
				IPHeaders: []string{"CF-Connecting-IP"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var od data.Data

			hstub := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				od = *data.GetData(r)
			})
			c := New(hstub)
			recorder := &httptest.ResponseRecorder{}
			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)

			req.RemoteAddr = test.remoteAddr
			for k, v := range test.headers {
				req.Header.Add(k, v)
			}

			err := c.WithTrustedProxies(test.trustedProxies)

			require.NoError(t, err)
			c.ServeHTTP(recorder, req)

			assert.Equal(t, test.expectedData, od)
		})
	}
}
