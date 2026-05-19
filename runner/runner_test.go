package runner

import (
	"testing"

	asnmap "github.com/projectdiscovery/asnmap/libs"

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
