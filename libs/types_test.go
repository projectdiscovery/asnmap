package asnmap

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIdentifyInput(t *testing.T) {
	tt := []struct {
		name           string
		input          string
		expectedOutput interface{}
	}{
		{"IP", "10.101.101.10", IP("10.101.101.10")},
		{"ASN", "AS14421", ASN("14421")},
		{"Org", "PPLINKNET", Org("PPLINKNET")},
		{"Org", "AS", Org("AS")},
		{"Org", "AS-CHOOPA", Org("AS-CHOOPA")},
		{"Top level domain", "google.com", Domain("google.com")},
		{"Country level domain", "bbc.co.uk", Domain("bbc.co.uk")},
		{"Second level domain", "cornell.edu", Domain("cornell.edu")},
		{"Third level domain", "bigstuff.cornell.edu", Domain("bigstuff.cornell.edu")},
		{"Fourth level domain", "www.bass.blm.gov", Domain("www.bass.blm.gov")},
		{"Domain with number", "www.99acres.com", Domain("www.99acres.com")},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			res := IdentifyInput(tc.input)
			require.Equal(t, res, tc.expectedOutput)
		})
	}
}
