package main

import (
	"os"
	"os/signal"

	"github.com/projectdiscovery/asnmap/runner"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// Parse the command line flags and read config files
	options := runner.ParseOptions()

	asnmapRunner, err := runner.New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	defer func() {
		_ = asnmapRunner.Close()
	}()

	// Setup graceful exits
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			// Close should be called explicitly as it doesn't honor
			_ = asnmapRunner.Close()
			os.Exit(1)
		}
	}()

	if err := asnmapRunner.Run(); err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}
}
