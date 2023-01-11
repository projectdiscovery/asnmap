package main

import (
	"bufio"
	"encoding/csv"
	"os"
	"reflect"
	"sync"

	asnmap "github.com/projectdiscovery/asnmap/libs"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

var options *Options

// Process Function makes request to client returns response
func process(wg *sync.WaitGroup, inputchan chan interface{}, outputchan chan []asnmap.Response, client *asnmap.Client) {
	defer wg.Done()
	var err error
	for value := range inputchan {
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}

		if _, ok := value.(asnmap.Domain); ok {
			resolvedIps, err := asnmap.ResolveDomain(reflect.ValueOf(value).String(), options.Resolvers...)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
			}
			if len(resolvedIps) == 0 {
				gologger.Verbose().Msgf("No records found for %v", reflect.ValueOf(value).String())
			} else {
				for _, v := range resolvedIps {
					wg.Add(1)
					go func(v string, input interface{}) {
						defer wg.Done()
						ls, err := client.GetData(asnmap.IP(v), input)
						if err != nil {
							gologger.Fatal().Msgf("%s\n", err)
						}
						if len(ls) > 0 {
							outputchan <- ls
						}
					}(v, value)
				}
			}
		} else {
			wg.Add(1)
			go func(value interface{}) {
				defer wg.Done()
				ls, err := client.GetData(value, value)
				if err != nil {
					gologger.Fatal().Msgf("%s\n", err)
				}
				if len(ls) > 0 {
					outputchan <- ls
				} else {
					gologger.Verbose().Msgf("No records found for %v", reflect.ValueOf(value).String())
				}
			}(value)
		}
	}
}

func prepareInput(wg *sync.WaitGroup, inputchan chan interface{}) {
	defer wg.Done()
	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			_ = options.FileInput.Set(scanner.Text())
		}
	}

	if options.FileInput != nil {
		for _, item := range options.FileInput {
			v := asnmap.IdentifyInput(item)
			inputchan <- v
		}
	}

	if options.Asn != nil {
		for _, item := range options.Asn {
			inputchan <- asnmap.ASN(item[2:])
		}
	}

	if options.Ip != nil {
		for _, item := range options.Ip {
			inputchan <- asnmap.IP(item)
		}
	}

	if options.Domain != nil {
		for _, item := range options.Domain {
			inputchan <- asnmap.Domain(item)
		}
	}

	if options.Org != nil {
		for _, item := range options.Org {
			inputchan <- asnmap.Org(item)
		}
	}

	close(inputchan)
}

func main() {
	options = parseOptions()

	client, err := asnmap.NewClient()
	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}
	if len(options.Proxy) > 0 {
		if proxyURL, err := client.SetProxy(options.Proxy); err != nil {
			gologger.Fatal().Msgf("Could not set proxy: %s", err)
		} else {
			gologger.Info().Msgf("Using %s proxy %s", proxyURL.Scheme, proxyURL.String())
		}
	}
	if options.OutputFile != "" {
		if _, err := os.Stat(options.OutputFile); err == nil {
			err := os.Remove(options.OutputFile)
			if err != nil {
				gologger.Fatal().Msg(err.Error())
			}
		}
	}

	if options.DisplayInCSV {
		if options.OutputFile != "" {
			file, err := os.OpenFile(options.OutputFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
			if err != nil {
				gologger.Fatal().Msg(err.Error())
			}
			options.Output = file
		}
		w := csv.NewWriter(options.Output)
		w.Comma = '|'

		for _, record := range csvHeaders {
			if err := w.Write(record); err != nil {
				gologger.Fatal().Msg(err.Error())
			}
		}
		w.Flush()
	}

	var wg sync.WaitGroup
	var wgoutput sync.WaitGroup
	inputchan := make(chan interface{})
	outputchan := make(chan []asnmap.Response)

	wg.Add(1)
	go prepareInput(&wg, inputchan)
	wg.Add(1)
	go process(&wg, inputchan, outputchan, client)
	wgoutput.Add(1)
	go prepareOutput(&wgoutput, outputchan)

	wg.Wait()

	close(outputchan)
	wgoutput.Wait()
}
