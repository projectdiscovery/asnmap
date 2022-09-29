package main

import (
	"encoding/csv"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	asnmap "github.com/projectdiscovery/asnmap/libs"

	"github.com/projectdiscovery/gologger"
)

var csvHeaders = [][]string{{"timestamp", "input", "as_number", "as_name", "as_country", "as_range"}}

func isIPv6(address string) bool {
	return strings.Count(address, ":") >= 2
}

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
		if !isIPv6(ip.String()) {
			filteredIps = append(filteredIps, ip)
		}
	}
	return filteredIps
}

// writeOutput either to file or to stdout
func writeOutput(wg *sync.WaitGroup, output []asnmap.Response) {
	defer wg.Done()
	if options.OutputFile != "" {
		file, err := os.OpenFile(options.OutputFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		options.Output = file
	}

	if options.DisplayInJSON {
		result := asnmap.GetFormattedDataInJson(output)
		fmt.Fprintf(options.Output, "%v\n", string(result))
	} else if options.DisplayInCSV {
		results := asnmap.GetFormattedDataInCSV(output)
		writeToCsv(results)
	} else {
		result := filterIPv6(asnmap.GetCIDR(output))
		for _, cidr := range result {
			_, err := fmt.Fprintf(options.Output, "%v\n", cidr)
			if err != nil {
				gologger.Fatal().Msg(err.Error())
			}
		}
	}
}

// PrepareOutput display output as per options.go passed from command line arguments
func prepareOutput(wg *sync.WaitGroup, outputchan chan []asnmap.Response) {
	defer wg.Done()

	for o := range outputchan {
		wg.Add(1)
		go writeOutput(wg, o)
	}
}
