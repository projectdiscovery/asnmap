package runner

import (
	"testing"

	asnmap "github.com/projectdiscovery/asnmap/libs"

	"github.com/stretchr/testify/require"
)

func TestRunner(t *testing.T) {
	tests := []struct {
		name           string
		options        *Options
		expectedOutput []*asnmap.Response
	}{
		{
			name: "IP",
			options: &Options{
				Ip: []string{"104.16.99.52"},
			},
			expectedOutput: []*asnmap.Response{
				{
					FirstIp: "104.16.0.0",
					LastIp:  "104.20.63.255",
					Input:   "104.16.99.52",
					ASN:     13335,
					Country: "US",
					Org:     "cloudflarenet"},
			},
		},
		{
			name: "ASN",
			options: &Options{
				Asn: []string{"AS14421"},
			},
			expectedOutput: []*asnmap.Response{
				{
					FirstIp: "216.101.17.0",
					LastIp:  "216.101.17.255",
					Input:   "14421",
					ASN:     14421,
					Country: "US",
					Org:     "theravance"},
			},
		},
		{
			name: "Org",
			options: &Options{
				Org: []string{"microsoft"},
			},
			expectedOutput: []*asnmap.Response{
				{
					FirstIp: "151.207.40.0",
					LastIp:  "151.207.47.255",
					Input:   "microsoft",
					ASN:     12076,
					Country: "US",
					Org:     "microsoft"},
				{
					FirstIp: "170.110.229.0",
					LastIp:  "170.110.229.255",
					Input:   "microsoft",
					ASN:     12076,
					Country: "US",
					Org:     "microsoft",
				},
				{
					FirstIp: "2608:1c1:6::",
					LastIp:  "2608:1c1:8:ffff:ffff:ffff:ffff:ffff",
					Input:   "microsoft",
					ASN:     12076,
					Country: "US",
					Org:     "microsoft",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.options.OnResult = func(o []*asnmap.Response) {
				require.Equal(t, tt.expectedOutput, o)
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
				// // Expecting true from comparision
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
