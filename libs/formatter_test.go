package asnmap

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetFormattedDataInJson(t *testing.T) {
	tt := []struct {
		name           string
		inputResponse  []*Response
		expectedOutput *Result
	}{
		{
			name: "ASN",
			inputResponse: []*Response{
				{
					FirstIp: "216.101.17.0",
					LastIp:  "216.101.17.255",
					Input:   "AS14421",
					ASN:     14421,
					Country: "US",
					Org:     "THERAVANCE"},
			},
			expectedOutput: &Result{
				Timestamp:  "",
				Input:      "AS14421",
				ASN:        "AS14421",
				ASN_org:    "THERAVANCE",
				AS_country: "US",
				AS_range:   []string{"216.101.17.0/24"},
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			output, err := GetFormattedDataInJson(tc.inputResponse)
			require.Nil(t, err)
			var actualOutput *Result
			err = json.Unmarshal(output, &actualOutput)
			require.Nil(t, err)

			// Ignoring timestamp from acutal output
			actualOutput.Timestamp = ""
			require.Equal(t, actualOutput, tc.expectedOutput)
		})
	}
}

func TestGetFormattedDataInCSV(t *testing.T) {
	tt := []struct {
		name           string
		inputResponse  []*Response
		expectedOutput [][]string
	}{
		{
			name: "ASN",
			inputResponse: []*Response{
				{
					FirstIp: "216.101.17.0",
					LastIp:  "216.101.17.255",
					Input:   "14421",
					ASN:     14421,
					Country: "US",
					Org:     "THERAVANCE",
				},
			},
			expectedOutput: [][]string{
				{"", "AS14421", "AS14421", "THERAVANCE", "US", "216.101.17.0/24"},
			},
		},
		{
			name: "Org",
			inputResponse: []*Response{
				{
					FirstIp: "45.239.52.0",
					LastIp:  "45.239.55.255",
					Input:   "pplinknet",
					ASN:     268353,
					Country: "BR",
					Org:     "PPLINKNET SERVICOS DE COMUNICACAO LTDA - ME",
				},
				{
					FirstIp: "2804:4fd8::",
					LastIp:  "2804:4fd8:ffff:ffff:ffff:ffff:ffff:ffff",
					Input:   "pplinknet",
					ASN:     268353,
					Country: "BR",
					Org:     "PPLINKNET SERVICOS DE COMUNICACAO LTDA - ME",
				},
			},
			expectedOutput: [][]string{
				{"", "pplinknet", "AS268353", "PPLINKNET SERVICOS DE COMUNICACAO LTDA - ME", "BR", "45.239.52.0/22"},
				{"", "pplinknet", "AS268353", "PPLINKNET SERVICOS DE COMUNICACAO LTDA - ME", "BR", "2804:4fd8::/32"},
			},
		},
		{
			name: "IP",
			inputResponse: []*Response{
				{
					FirstIp: "104.16.0.0",
					LastIp:  "104.21.127.255",
					Input:   "104.16.99.52",
					ASN:     13335,
					Country: "US",
					Org:     "CLOUDFLARENET",
				},
			},
			expectedOutput: [][]string{
				{"", "104.16.99.52", "AS13335", "CLOUDFLARENET", "US", "104.16.0.0/14,104.20.0.0/16,104.21.0.0/17"},
			},
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			actualOutput, err := GetFormattedDataInCSV(tc.inputResponse)
			require.Nil(t, err)

			// Ignoring timestamp from acutal output
			for _, output := range actualOutput {
				output[0] = ""
			}
			require.Equal(t, actualOutput, tc.expectedOutput)
		})
	}
}
