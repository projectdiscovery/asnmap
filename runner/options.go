package runner

import (
	"errors"
	"io"
	"os"
	"strings"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	fileutil "github.com/projectdiscovery/utils/file"
	updateutils "github.com/projectdiscovery/utils/update"
)

type OnResultCallback func([]*asnmap.Response)

var cfgFile string

type Options struct {
	FileInput          goflags.StringSlice
	Resolvers          goflags.StringSlice
	Asn                goflags.StringSlice
	Domain             goflags.StringSlice
	Ip                 goflags.StringSlice
	Org                goflags.StringSlice
	Proxy              goflags.StringSlice
	OutputFile         string
	Output             io.Writer
	DisplayInJSON      bool
	DisplayInCSV       bool
	Silent             bool
	Verbose            bool
	Version            bool
	DisplayIPv6        bool
	OnResult           OnResultCallback
	DisableUpdateCheck bool
}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	} else if options.Verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	}
}

// validateOptions validates different command line option combinations
func (options *Options) validateOptions() error {
	if options.Verbose && options.Silent {
		return errors.New("verbose and silent can't be used together")
	}

	if options.Asn == nil && options.Ip == nil && options.Org == nil && options.Domain == nil && !fileutil.HasStdin() && cfgFile == "" {
		return errors.New("no input defined")
	}

	if options.Asn != nil && (options.Ip != nil || options.Org != nil || options.Domain != nil) {
		return errors.New("Asn and other options like ip, org and domain can't be used together as input to get data")
	} else if options.Ip != nil && (options.Asn != nil || options.Org != nil || options.Domain != nil) {
		return errors.New("Ip and other options like asn, org and domain can't be used together as input to get data")
	} else if options.Org != nil && (options.Asn != nil || options.Ip != nil || options.Domain != nil) {
		return errors.New("Org and other options like asn, ip and domain can't be used together as input to get data")
	} else if options.Domain != nil && (options.Asn != nil || options.Ip != nil || options.Org != nil) {
		return errors.New("Domain and other options like asn, ip and org can't be used together as input to get data")
	}

	if options.DisplayInJSON && options.DisplayInCSV {
		return errors.New("Can either display in JSON or CSV.")
	}

	// validate asn input
	if options.Asn != nil {
		for _, asn := range options.Asn {
			if !strings.HasPrefix(strings.ToUpper(asn), "AS") {
				return errors.New("Invalid ASN given. it should start with prefix 'AS', example : AS14421")
			}
		}
	}
	return nil
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Go CLI and Library for quickly mapping organization network ranges using ASN information.`)

	// Input
	flagSet.CreateGroup("input", "Input",
		flagSet.StringSliceVarP(&options.Asn, "asn", "a", nil, "target asn to lookup, example: -a AS5650", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Ip, "ip", "i", nil, "target ip to lookup, example: -i 100.19.12.21, -i 2a10:ad40:: ", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Domain, "domain", "d", nil, "target domain to lookup, example: -d google.com, -d facebook.com", goflags.FileNormalizedStringSliceOptions),
		flagSet.StringSliceVar(&options.Org, "org", nil, "target organization to lookup, example: -org GOOGLE", goflags.StringSliceOptions),
		flagSet.StringSliceVarP(&options.FileInput, "file", "f", nil, "targets to lookup from file", goflags.CommaSeparatedStringSliceOptions),
	)

	// Configs
	flagSet.CreateGroup("configs", "Configurations",
		flagSet.StringVar(&cfgFile, "config", "", "path to the asnmap configuration file"),
		flagSet.StringSliceVarP(&options.Resolvers, "resolvers", "r", nil, "list of resolvers to use", goflags.FileCommaSeparatedStringSliceOptions),
		flagSet.StringSliceVarP(&options.Proxy, "proxy", "p", nil, "list of proxy to use (comma separated or file input)", goflags.FileCommaSeparatedStringSliceOptions),
	)

	// Update
	flagSet.CreateGroup("update", "Update",
		flagSet.CallbackVarP(GetUpdateCallback(), "update", "up", "update asnmap to latest version"),
		flagSet.BoolVarP(&options.DisableUpdateCheck, "disable-update-check", "duc", false, "disable automatic asnmap update check"),
	)

	// Output
	flagSet.CreateGroup("output", "Output",
		flagSet.StringVarP(&options.OutputFile, "output", "o", "", "file to write output to"),
		flagSet.BoolVarP(&options.DisplayInJSON, "json", "j", false, "display json format output"),
		flagSet.BoolVarP(&options.DisplayInCSV, "csv", "c", false, "display csv format output"),
		flagSet.BoolVar(&options.DisplayIPv6, "v6", false, "display ipv6 cidr ranges in cli output"),
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "display verbose output"),
		flagSet.BoolVar(&options.Silent, "silent", false, "display silent output"),
		flagSet.BoolVar(&options.Version, "version", false, "show version of the project"),
	)

	if err := flagSet.Parse(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	// Read the inputs and configure the logging
	options.configureOutput()

	if options.OutputFile == "" {
		options.Output = os.Stdout
	}

	if cfgFile != "" {
		if err := flagSet.MergeConfigFile(cfgFile); err != nil {
			gologger.Fatal().Msgf("Could not read config file.")
		}
	}

	if options.Version {
		gologger.Info().Msgf("Current Version: %s\n", version)
		os.Exit(0)
	}

	showBanner()

	if !options.DisableUpdateCheck {
		latestVersion, err := updateutils.GetToolVersionCallback("asnmap", version)()
		if err != nil {
			if options.Verbose {
				gologger.Error().Msgf("asnmap version check failed: %v", err.Error())
			}
		} else {
			gologger.Info().Msgf("Current asnmap version %v %v", version, updateutils.GetVersionDescription(version, latestVersion))
		}
	}

	if err := options.validateOptions(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	return options
}
