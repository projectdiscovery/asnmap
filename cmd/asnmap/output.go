package main

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"sync"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	iputil "github.com/projectdiscovery/utils/ip"

	"github.com/projectdiscovery/gologger"
)

var csvHeaders = [][]string{{"timestamp", "input", "as_number", "as_name", "as_country", "as_range"}}

func writeToCsv(records [][]string) {
	w := csv.NewWriter(options.Output)
	w.Comma = '|'

	for _, record := range records {
		if err := w.Write(record); err != nil {
			gologger.Fatal().Msg(err.Error())
		}
	}

	w.Flush()

	if err := w.Error(); err != nil {
		gologger.Fatal().Msg(err.Error())
	}
}

// filterIPv6() returns both IPv6, IPv4 if DisplayIPv6 is enabled, else return only IPv4
func filterIPv6(ips []*net.IPNet) []*net.IPNet {
	if options.DisplayIPv6 {
		return ips
	}

	var filteredIps []*net.IPNet
	for _, ip := range ips {
		if !iputil.IsIPv6(ip.String()) {
			filteredIps = append(filteredIps, ip)
		}
	}
	return filteredIps
}

// writeOutput either to file or to stdout
func writeOutput(wg *sync.WaitGroup, output []*asnmap.Response) {
	defer wg.Done()
	if options.OutputFile != "" {
		file, err := os.OpenFile(options.OutputFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		options.Output = file
	}

	if options.DisplayInJSON {
		result, err := asnmap.GetFormattedDataInJson(output)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		fmt.Fprintf(options.Output, "%v\n", string(result))
	} else if options.DisplayInCSV {
		results, err := asnmap.GetFormattedDataInCSV(output)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		writeToCsv(results)
	} else {
		cidrs, err := asnmap.GetCIDR(output)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		result := filterIPv6(cidrs)
		for _, cidr := range result {
			_, err := fmt.Fprintf(options.Output, "%v\n", cidr)
			if err != nil {
				gologger.Fatal().Msg(err.Error())
			}
		}
	}
}

// PrepareOutput display output as per options.go passed from command line arguments
func prepareOutput(wg *sync.WaitGroup, outputchan chan []*asnmap.Response) {
	defer wg.Done()

	for o := range outputchan {
		wg.Add(1)
		go writeOutput(wg, o)
	}
}
