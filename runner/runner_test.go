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
					FirstIp: "102.129.206.0",
					LastIp:  "127.255.255.255",
					Input:   "104.16.99.52",
					ASN:     9498,
					Country: "IN",
					Org:     "BBIL-AP BHARTI Airtel Ltd."},
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
					Org:     "THERAVANCE"},
			},
		},
		{
			name: "Org",
			options: &Options{
				Org: []string{"PPLINK"},
			},
			expectedOutput: []*asnmap.Response{
				{
					FirstIp: "45.239.52.0",
					LastIp:  "45.239.55.255",
					Input:   "PPLINK",
					ASN:     268353,
					Country: "BR",
					Org:     "PPLINKNET SERVICOS DE COMUNICACAO LTDA - ME"},
				{
					FirstIp: "2804:4fd8::",
					LastIp:  "2804:4fd8:ffff:ffff:ffff:ffff:ffff:ffff",
					Input:   "PPLINK",
					ASN:     268353,
					Country: "BR",
					Org:     "PPLINKNET SERVICOS DE COMUNICACAO LTDA - ME"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.options.OnResult = func(o []*asnmap.Response) {
				require.Equal(t, o, tt.expectedOutput)
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
				Org:     "GOOGLE",
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
	for ind := range respA {
		if respA[ind].ASN == respB.ASN && respA[ind].Org == respB.Org {
			return true
		}
	}

	return false
}
