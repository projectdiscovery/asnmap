package asnmap

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeAPI answers like asnmap-server for the inputs used in these tests
func fakeAPI(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	switch {
	case q.Get("ip") == "100.19.12.21":
		_, _ = w.Write([]byte(`[{"first_ip":"100.19.0.0","last_ip":"100.19.255.255","asn":701,"country":"US","org":"uunet"}]`))
	case q.Get("asn") == "14421":
		_, _ = w.Write([]byte(`[{"first_ip":"216.101.17.0","last_ip":"216.101.17.255","asn":14421,"country":"US","org":"theravance"}]`))
	case q.Get("asn") == "7712":
		_, _ = w.Write([]byte(`[{"first_ip":"118.67.200.0","last_ip":"118.67.203.255","asn":7712,"country":"KH","org":"cne-as-ap"},{"first_ip":"118.67.204.0","last_ip":"118.67.207.255","asn":7712,"country":"KH","org":"cne-as-ap"}]`))
	case q.Get("org") == "PPLINKNET":
		_, _ = w.Write([]byte(`[{"first_ip":"45.239.52.0","last_ip":"45.239.55.255","asn":268353,"country":"BR","org":"PPLINKNET"}]`))
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"no results found"}`))
	}
}

func TestGetData(t *testing.T) {
	client := newTestClient(t, fakeAPI)
	noResults := "bad request: {\"error\":\"no results found\"}"

	tt := []struct {
		name     string
		input    string
		expected []*Response
		err      string
	}{
		{"ip", "100.19.12.21", []*Response{
			{FirstIp: "100.19.0.0", LastIp: "100.19.255.255", Input: "100.19.12.21", ASN: 701, Country: "US", Org: "uunet"},
		}, ""},
		{"ip not found", "255.100.100.100", nil, noResults},
		{"asn", "AS14421", []*Response{
			{FirstIp: "216.101.17.0", LastIp: "216.101.17.255", Input: "14421", ASN: 14421, Country: "US", Org: "theravance"},
		}, ""},
		{"asn number", "14421", []*Response{
			{FirstIp: "216.101.17.0", LastIp: "216.101.17.255", Input: "14421", ASN: 14421, Country: "US", Org: "theravance"},
		}, ""},
		{"asn multiple ranges", "AS7712", []*Response{
			{FirstIp: "118.67.200.0", LastIp: "118.67.203.255", Input: "7712", ASN: 7712, Country: "KH", Org: "cne-as-ap"},
			{FirstIp: "118.67.204.0", LastIp: "118.67.207.255", Input: "7712", ASN: 7712, Country: "KH", Org: "cne-as-ap"},
		}, ""},
		{"asn not found", "AS1123", nil, noResults},
		{"org", "PPLINKNET", []*Response{
			{FirstIp: "45.239.52.0", LastIp: "45.239.55.255", Input: "PPLINKNET", ASN: 268353, Country: "BR", Org: "PPLINKNET"},
		}, ""},
		{"org not found", "RANDOM_TEXT", nil, noResults},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			got, err := client.GetData(tc.input)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.Nil(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestClientTimeout(t *testing.T) {
	client, err := NewClient()
	require.Nil(t, err)
	require.Equal(t, requestTimeout, client.http.Timeout)

	// setting a proxy swaps the transport and must keep the timeout
	proxySrv := httptest.NewServer(http.NotFoundHandler())
	defer proxySrv.Close()
	_, err = client.SetProxy([]string{proxySrv.URL})
	require.Nil(t, err)
	require.Equal(t, requestTimeout, client.http.Timeout)
}
