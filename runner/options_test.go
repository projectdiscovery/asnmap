package runner

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateASNInput(t *testing.T) {
	for _, asn := range []string{"AS13335", "as13335", "13335"} {
		options := &Options{Asn: []string{asn}}
		require.NoError(t, options.validateOptions(), asn)
	}
	for _, asn := range []string{"ASX", "google", "AS"} {
		options := &Options{Asn: []string{asn}}
		require.Error(t, options.validateOptions(), asn)
	}
}
