package runner

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/gologger/writer"

	"github.com/stretchr/testify/require"
)

// newTestServer points the client at a local server instead of the live API
func newTestServer(t *testing.T, handler http.HandlerFunc) {
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv("SERVER_URL", srv.URL)

	apiKey := asnmap.PDCPApiKey
	asnmap.PDCPApiKey = "test"
	t.Cleanup(func() { asnmap.PDCPApiKey = apiKey })
}

func TestRunner(t *testing.T) {
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("ip") == "104.16.99.52":
			_, _ = w.Write([]byte(`[{"first_ip":"104.16.0.0","last_ip":"104.31.255.255","asn":13335,"country":"US","org":"cloudflarenet"}]`))
		case q.Get("asn") == "14421":
			_, _ = w.Write([]byte(`[{"first_ip":"216.101.17.0","last_ip":"216.101.17.255","asn":14421,"country":"US","org":"theravance"}]`))
		case q.Get("org") == "microsoft":
			_, _ = w.Write([]byte(`[{"first_ip":"13.64.0.0","last_ip":"13.107.255.255","asn":8075,"country":"US","org":"microsoft"}]`))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"no results found"}`))
		}
	})

	tests := []struct {
		name     string
		options  *Options
		expected []*asnmap.Response
	}{
		{"IP", &Options{Ip: []string{"104.16.99.52"}}, []*asnmap.Response{
			{FirstIp: "104.16.0.0", LastIp: "104.31.255.255", Input: "104.16.99.52", ASN: 13335, Country: "US", Org: "cloudflarenet"},
		}},
		{"ASN", &Options{Asn: []string{"AS14421"}}, []*asnmap.Response{
			{FirstIp: "216.101.17.0", LastIp: "216.101.17.255", Input: "14421", ASN: 14421, Country: "US", Org: "theravance"},
		}},
		{"Org", &Options{Org: []string{"microsoft"}}, []*asnmap.Response{
			{FirstIp: "13.64.0.0", LastIp: "13.107.255.255", Input: "microsoft", ASN: 8075, Country: "US", Org: "microsoft"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []*asnmap.Response
			tt.options.OnResult = func(o []*asnmap.Response) { got = append(got, o...) }
			r, err := New(tt.options)
			require.Nil(t, err)
			t.Cleanup(func() { _ = r.Close() })

			require.Nil(t, r.prepareInput())
			require.Nil(t, r.process())
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestProcessForDomainInput(t *testing.T) {
	// the domain still resolves through DNS, only the API is local
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"first_ip":"142.250.0.0","last_ip":"142.250.82.255","asn":15169,"country":"US","org":"google"}]`))
	})

	var got []*asnmap.Response
	options := &Options{
		Domain:   []string{"google.com"},
		OnResult: func(o []*asnmap.Response) { got = append(got, o...) },
	}
	r, err := New(options)
	require.Nil(t, err)
	t.Cleanup(func() { _ = r.Close() })

	require.Nil(t, r.prepareInput())
	require.Nil(t, r.process())
	// every resolved IP maps to the same range, so it is reported once
	require.Equal(t, []*asnmap.Response{
		{FirstIp: "142.250.0.0", LastIp: "142.250.82.255", Input: "google.com", ASN: 15169, Country: "US", Org: "google"},
	}, got)
}

func TestProcessSkipsFailedInput(t *testing.T) {
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("asn") == "1" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"no results found"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"first_ip":"1.1.1.0","last_ip":"1.1.1.255","asn":13335,"country":"US","org":"cloudflarenet"}]`))
	})

	var got []*asnmap.Response
	// AS1 sorts first, so a failure there must not stop AS13335
	options := &Options{
		Asn:      []string{"AS1", "AS13335"},
		OnResult: func(o []*asnmap.Response) { got = append(got, o...) },
	}
	r, err := New(options)
	require.Nil(t, err)
	defer func() { _ = r.Close() }()

	require.Nil(t, r.prepareInput())
	require.Nil(t, r.process())
	require.Len(t, got, 1)
	require.Equal(t, 13335, got[0].ASN)
}

func TestProcessConcurrent(t *testing.T) {
	var inFlight, maxInFlight atomic.Int32
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			m := maxInFlight.Load()
			if n <= m || maxInFlight.CompareAndSwap(m, n) {
				break
			}
		}
		// hold each request so overlapping ones are observable
		time.Sleep(50 * time.Millisecond)
		_, _ = fmt.Fprintf(w, `[{"first_ip":"1.1.1.0","last_ip":"1.1.1.255","asn":%s,"country":"US","org":"test"}]`, r.URL.Query().Get("asn"))
	})

	var asns []string
	for i := 1; i <= 20; i++ {
		asns = append(asns, fmt.Sprintf("AS%d", i))
	}
	var (
		mu  sync.Mutex
		got = map[int]bool{}
	)
	options := &Options{
		Asn:     asns,
		Threads: 5,
		OnResult: func(o []*asnmap.Response) {
			mu.Lock()
			defer mu.Unlock()
			for _, r := range o {
				got[r.ASN] = true
			}
		},
	}
	r, err := New(options)
	require.Nil(t, err)
	defer func() { _ = r.Close() }()

	require.Nil(t, r.prepareInput())
	require.Nil(t, r.process())
	require.Len(t, got, 20)
	require.Greater(t, maxInFlight.Load(), int32(1))
	require.LessOrEqual(t, maxInFlight.Load(), int32(5))
}

func TestSkippedInputIsReported(t *testing.T) {
	newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("asn") == "1" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"no results found"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"first_ip":"1.1.1.0","last_ip":"1.1.1.255","asn":13335,"country":"US","org":"cloudflarenet"}]`))
	})

	capture := &logCapture{}
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	gologger.DefaultLogger.SetFormatter(formatter.NewCLI(true))
	gologger.DefaultLogger.SetWriter(capture)
	t.Cleanup(func() {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
		gologger.DefaultLogger.SetFormatter(formatter.NewCLI(false))
		gologger.DefaultLogger.SetWriter(writer.NewCLI())
	})

	options := &Options{Asn: []string{"AS1", "AS13335"}}
	r, err := New(options)
	require.Nil(t, err)
	t.Cleanup(func() { _ = r.Close() })

	require.Nil(t, r.prepareInput())
	require.Nil(t, r.process())

	logged := capture.String()
	require.Contains(t, logged, "[ERR] skipping AS1")
	require.NotContains(t, logged, "[WRN]")
}

type logCapture struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *logCapture) Write(data []byte, _ levels.Level) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf.Write(data)
}

func (c *logCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}
