package asnmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentifyInput(t *testing.T) {
	tt := []struct {
		name           string
		input          string
		expectedOutput InputType
	}{
		{"IP", "10.101.101.10", IP},
		{"ASN", "AS14421", ASN},
		{"Org", "PPLINKNET", Org},
		{"Org", "AS", Org},
		{"Org", "AS-CHOOPA", Org},
		{"Top level domain", "google.com", Domain},
		{"Country level domain", "bbc.co.uk", Domain},
		{"Second level domain", "cornell.edu", Domain},
		{"Third level domain", "bigstuff.cornell.edu", Domain},
		{"Fourth level domain", "www.bass.blm.gov", Domain},
		{"Domain with number", "www.99acres.com", Domain},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res := IdentifyInput(tc.input)
			require.Equal(t, res, tc.expectedOutput)
		})
	}
}

func TestMapToResults(t *testing.T) {
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
			output, err := MapToResults(tc.inputResponse)
			require.Nil(t, err)

			if len(output) == 0 {
				t.Fatalf("Expected at least one result, got none.")
			}

			// Ignoring timestamp from acutal output
			output[0].Timestamp = ""
			require.Equal(t, tc.expectedOutput, output[0])
		})
	}
}
