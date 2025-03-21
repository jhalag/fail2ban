package data

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		expectedData *Data
	}{
		{
			name: "single IP",
			expectedData: &Data{
				RemoteIP: "192.0.2.1",
			},
		},
		{
			name: "IP via proxy",
			expectedData: &Data{
				RemoteIP:        "172.0.2.1",
				ViaTrustedProxy: "10.10.0.1",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			req, err := SetData(req, test.expectedData)
			require.NoError(t, err)

			got := GetData(req)
			assert.Equal(t, test.expectedData, got)
		})
	}
}

func TestGetData_InvalidData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		req          func(*testing.T) *http.Request
		expectedData *Data
	}{
		{
			name: "data",
			req: func(t *testing.T) *http.Request {
				t.Helper()

				req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
				req, err := SetData(req, &Data{
					RemoteIP: "192.0.2.1",
				})
				require.NoError(t, err)

				return req
			},
			expectedData: &Data{
				RemoteIP: "192.0.2.1",
			},
		},
		{
			name: "no data",
			req: func(t *testing.T) *http.Request {
				t.Helper()

				return httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)
			},
		},
		{
			name: "invalid data",
			req: func(t *testing.T) *http.Request {
				t.Helper()
				req := httptest.NewRequest(http.MethodGet, "https://example.com/foo", nil)

				return req.WithContext(context.WithValue(req.Context(), contextDataKey, true))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			data := GetData(test.req(t))
			assert.Equal(t, test.expectedData, data)
		})
	}
}
