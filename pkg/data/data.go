// Package data provides a way to store data in the request context.
package data

import (
	"context"
	"net/http"
)

type key string

const contextDataKey key = "data"

type Data struct {
	RemoteIP        string
	ViaTrustedProxy string // If request came in via a trusted proxy, this contains it's IP
}

// SetData stores the data in the request context.
func SetData(r *http.Request, d *Data) (*http.Request, error) {
	return r.WithContext(context.WithValue(r.Context(), contextDataKey, d)), nil
}

// GetData returns the data stored in the request context.
func GetData(req *http.Request) *Data {
	if data, ok := req.Context().Value(contextDataKey).(*Data); ok {
		return data
	}

	return nil
}
