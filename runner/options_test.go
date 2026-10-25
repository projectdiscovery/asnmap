package runner

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/goflags"
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

func TestOrgFlagReadsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orgs.txt")
	err := os.WriteFile(path, []byte("Google, Inc\n\n# comment\nCloudflare\n"), 0o644)
	require.NoError(t, err)

	options := parseInputFlags(t, "-org", path)
	require.Equal(t, goflags.StringSlice{"Google, Inc", "Cloudflare"}, options.Org)

	inline := parseInputFlags(t, "-org", "Google, Inc")
	require.Equal(t, goflags.StringSlice{"Google, Inc"}, inline.Org)
}

func parseInputFlags(t *testing.T, args ...string) *Options {
	t.Helper()
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.CommandLine = flag.NewFlagSet("asnmap", flag.ContinueOnError)
	setInputFlags(flagSet, options)
	require.NoError(t, flagSet.CommandLine.Parse(args))
	return options
}
