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
