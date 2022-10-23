package main

import (
	"sync"
	"testing"

	asnmap "github.com/projectdiscovery/asnmap/libs"

	"github.com/stretchr/testify/require"
)

func TestProcess(t *testing.T) {
	tests := []struct {
		name           string
		inputchan      chan interface{}
		outputchan     chan []asnmap.Response
		options        Options
		expectedOutput []asnmap.Response
	}{
		{
			name:       "IP",
			inputchan:  make(chan interface{}),
			outputchan: make(chan []asnmap.Response),
			options: Options{
				Ip: []string{"104.16.99.52"},
			},
			expectedOutput: []asnmap.Response{
				{
					FirstIp: "104.16.0.0",
					LastIp:  "104.21.127.255",
					Input:   "104.16.99.52",
					ASN:     13335,
					Country: "US",
					Org:     "CLOUDFLARENET"},
			},
		},
		{
			name:       "ASN",
			inputchan:  make(chan interface{}),
			outputchan: make(chan []asnmap.Response),
			options: Options{
				Asn: []string{"AS14421"},
			},
			expectedOutput: []asnmap.Response{
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
			name:       "Org",
			inputchan:  make(chan interface{}),
			outputchan: make(chan []asnmap.Response),
			options: Options{
				Org: []string{"PPLINK"},
			},
			expectedOutput: []asnmap.Response{
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
			var wg sync.WaitGroup
			options = &tt.options
			client := asnmap.NewClient()

			wg.Add(1)
			go prepareInput(&wg, tt.inputchan)

			wg.Add(1)
			go process(&wg, tt.inputchan, tt.outputchan, client)

			var wgoutput sync.WaitGroup

			wgoutput.Add(1)
			go func(outputchan chan []asnmap.Response) {
				defer wgoutput.Done()
				for o := range outputchan {
					require.Equal(t, o, tt.expectedOutput)
				}
			}(tt.outputchan)

			wg.Wait()

			close(tt.outputchan)
			wgoutput.Wait()
		})
	}
}

func TestProcessForDomainInput(t *testing.T) {
	tests := []struct {
		name           string
		inputchan      chan interface{}
		outputchan     chan []asnmap.Response
		options        Options
		expectedOutput asnmap.Response
	}{
		{
			name:       "Domain",
			inputchan:  make(chan interface{}),
			outputchan: make(chan []asnmap.Response),
			options: Options{
				Domain: []string{"google.com"},
			},
			expectedOutput: asnmap.Response{
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
			var wg sync.WaitGroup
			options = &tt.options
			client := asnmap.NewClient()

			wg.Add(1)
			go prepareInput(&wg, tt.inputchan)

			wg.Add(1)
			go process(&wg, tt.inputchan, tt.outputchan, client)

			var wgoutput sync.WaitGroup

			wgoutput.Add(1)
			go func(outputchan chan []asnmap.Response) {
				defer wgoutput.Done()
				for o := range outputchan {
					x := compareResponse(o, tt.expectedOutput)
					// // Expecting true from comparision
					require.Equal(t, true, x)
				}
			}(tt.outputchan)

			wg.Wait()

			close(tt.outputchan)
			wgoutput.Wait()
		})
	}
}

// compareResponse compares ASN & ORG against given domain with expected output's ASN & ORG
// Have excluded IPs for now as they might change in future.
func compareResponse(respA []asnmap.Response, respB asnmap.Response) bool {
	compareResult := false

	for ind := range respA {
		if respA[ind].ASN == respB.ASN && respA[ind].Org == respB.Org {
			compareResult = true
		}
	}
	return compareResult
}
