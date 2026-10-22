package asnmap

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("SERVER_URL", srv.URL)

	apiKey := PDCPApiKey
	PDCPApiKey = "test"
	t.Cleanup(func() { PDCPApiKey = apiKey })

	client, err := NewClient()
	require.Nil(t, err)
	return client
}

func TestRetryOnRateLimit(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) <= 2 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`[{"first_ip":"1.1.1.0","last_ip":"1.1.1.255","asn":13335,"country":"US","org":"cloudflarenet"}]`))
	})

	got, err := client.GetData("AS13335")
	require.Nil(t, err)
	require.Len(t, got, 1)
	require.Equal(t, int32(3), calls.Load())
}

func TestRetryGivesUp(t *testing.T) {
	var calls atomic.Int32
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusServiceUnavailable)
	})

	_, err := client.GetData("AS13335")
	require.ErrorContains(t, err, "503")
	require.Equal(t, int32(maxRetries+1), calls.Load())
}

func TestUnexpectedStatusIsClear(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>forbidden</html>"))
	})

	_, err := client.GetData("AS13335")
	require.ErrorContains(t, err, "403")
	require.NotContains(t, err.Error(), "invalid character")
}

func TestRetryWait(t *testing.T) {
	require.Equal(t, time.Second, retryWait("", 0))
	require.Equal(t, 4*time.Second, retryWait("", 2))
	require.Equal(t, 2*time.Second, retryWait("soon", 1))
	require.Equal(t, 5*time.Second, retryWait("5", 0))
	require.Equal(t, maxRetryWait, retryWait("3600", 0))
}
