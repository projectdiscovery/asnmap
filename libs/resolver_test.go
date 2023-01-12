package asnmap

import (
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/stretchr/testify/require"
)

func TestResolveDomain(t *testing.T) {
	tt := []struct {
		name            string
		domain          string
		customresolvers []string
		expectedOutput  []string
	}{
		{"Resolve google.com using default resolvers", "google.com", []string{}, []string{"142.250.183.110"}},
		{"Resolve google.com using custom resolvers", "google.com", []string{"8.8.8.8"}, []string{"142.250.199.142"}},
		{"Resolve random domain name using custom resolvers", "somerandomdomainnamethatisfake.com", []string{"8.8.8.8"}, []string{}},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			i, err := ResolveDomain(tc.domain, tc.customresolvers...)
			require.Nil(t, err)
			gologger.Info().Msgf("%v resolve to %v", tc.domain, i)

			// If we are unable to resolve the domain, then ResolveDomain() returns an empty list
			// So for some unregistered domain, we will get an empty list.
			// Here we are not comparing the exact response for domain as IPs might get change in future.
			// Instead we are checking whether we are able to resolve domain to some IP or not.
			require.Falsef(t, len(i) == 0 && tc.domain != "somerandomdomainnamethatisfake.com", "Failed to resolve domain for test case: %v", tc.name)
		})
	}
}
