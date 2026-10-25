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

func TestRunner(t *testing.T) {
	// CIDR ranges and the exact set of records returned by the
	// upstream ASN service change over time. Pin only the stable
	// fields (ASN, Org, Country, Input) so the suite isn't broken
	// every time the database is updated.
	tests := []struct {
		name    string
		options *Options
		assert  func(t *testing.T, got []*asnmap.Response)
	}{
		{
			name:    "IP",
			options: &Options{Ip: []string{"104.16.99.52"}},
			assert: func(t *testing.T, got []*asnmap.Response) {
				require.NotEmpty(t, got)
				for _, r := range got {
					require.Equal(t, 13335, r.ASN)
					require.Equal(t, "cloudflarenet", r.Org)
					require.Equal(t, "US", r.Country)
					require.Equal(t, "104.16.99.52", r.Input)
				}
			},
		},
		{
			name:    "ASN",
			options: &Options{Asn: []string{"AS14421"}},
			assert: func(t *testing.T, got []*asnmap.Response) {
				require.NotEmpty(t, got)
				for _, r := range got {
					require.Equal(t, 14421, r.ASN)
					require.Equal(t, "14421", r.Input)
				}
			},
		},
		{
			name:    "Org",
			options: &Options{Org: []string{"microsoft"}},
			assert: func(t *testing.T, got []*asnmap.Response) {
				require.NotEmpty(t, got)
				for _, r := range got {
					require.Equal(t, 12076, r.ASN)
					require.Equal(t, "microsoft", r.Org)
					require.Equal(t, "microsoft", r.Input)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.options.OnResult = func(o []*asnmap.Response) {
				tt.assert(t, o)
			}
			r, err := New(tt.options)
			require.Nil(t, err)

			err = r.prepareInput()
			require.Nil(t, err)

			err = r.process()
			require.Nil(t, err)

			err = r.Close()
			require.Nil(t, err)
		})
	}
}

func TestProcessForDomainInput(t *testing.T) {
	tests := []struct {
		name           string
		inputchan      chan interface{}
		outputchan     chan []*asnmap.Response
		options        *Options
		expectedOutput *asnmap.Response
	}{
		{
			name:       "Domain",
			inputchan:  make(chan interface{}),
			outputchan: make(chan []*asnmap.Response),
			options: &Options{
				Domain: []string{"google.com"},
			},
			expectedOutput: &asnmap.Response{
				FirstIp: "142.250.0.0",
				LastIp:  "142.250.82.255",
				Input:   "google.com",
				ASN:     15169,
				Country: "US",
				Org:     "google",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.options.OnResult = func(o []*asnmap.Response) {
				x := compareResponse(o, tt.expectedOutput)
				// // Expecting true from comparison
				require.True(t, x)
			}

			r, err := New(tt.options)
			require.Nil(t, err)

			err = r.prepareInput()
			require.Nil(t, err)

			err = r.process()
			require.Nil(t, err)

			err = r.Close()
			require.Nil(t, err)
		})
	}
}

// compareResponse compares ASN & ORG against given domain with expected output's ASN & ORG
// Have excluded IPs for now as they might change in future.
func compareResponse(respA []*asnmap.Response, respB *asnmap.Response) bool {
	for _, r := range respA {
		if r.Equal(*respB) {
			return true
		}
	}

	return false
}

func TestProcessSkipsFailedInput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("asn") == "1" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"no results found"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"first_ip":"1.1.1.0","last_ip":"1.1.1.255","asn":13335,"country":"US","org":"cloudflarenet"}]`))
	}))
	defer srv.Close()
	t.Setenv("SERVER_URL", srv.URL)

	apiKey := asnmap.PDCPApiKey
	asnmap.PDCPApiKey = "test"
	defer func() { asnmap.PDCPApiKey = apiKey }()

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer srv.Close()
	t.Setenv("SERVER_URL", srv.URL)

	apiKey := asnmap.PDCPApiKey
	asnmap.PDCPApiKey = "test"
	defer func() { asnmap.PDCPApiKey = apiKey }()

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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("asn") == "1" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"no results found"}`))
			return
		}
		_, _ = w.Write([]byte(`[{"first_ip":"1.1.1.0","last_ip":"1.1.1.255","asn":13335,"country":"US","org":"cloudflarenet"}]`))
	}))
	defer srv.Close()
	t.Setenv("SERVER_URL", srv.URL)

	apiKey := asnmap.PDCPApiKey
	asnmap.PDCPApiKey = "test"
	t.Cleanup(func() { asnmap.PDCPApiKey = apiKey })

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
