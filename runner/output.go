package runner

import (
	"encoding/csv"
	"fmt"
	"net"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	iputil "github.com/projectdiscovery/utils/ip"
)

var csvHeaders = [][]string{{"timestamp", "input", "as_number", "as_name", "as_country", "as_range"}}

func (r *Runner) writeToCsv(records [][]string) error {
	w := csv.NewWriter(r.options.Output)
	w.Comma = '|'

	for _, record := range records {
		if err := w.Write(record); err != nil {
			return err
		}
	}

	w.Flush()

	return w.Error()
}

// filterIPv6() returns both IPv6, IPv4 if DisplayIPv6 is enabled, else return only IPv4
func (r *Runner) filterIPv6(ips []*net.IPNet) []*net.IPNet {
	if r.options.DisplayIPv6 {
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
func (r *Runner) writeOutput(output []*asnmap.Response) error {
	switch {
	case r.options.DisplayInJSON:
		result, err := asnmap.GetFormattedDataInJson(output)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(r.options.Output, "%v\n", string(result))
		return err
	case r.options.DisplayInCSV:
		results, err := asnmap.GetFormattedDataInCSV(output)
		if err != nil {
			return err
		}
		return r.writeToCsv(results)
	default:
		cidrs, err := asnmap.GetCIDR(output)
		if err != nil {
			return err
		}
		result := r.filterIPv6(cidrs)
		for _, cidr := range result {
			_, err := fmt.Fprintf(r.options.Output, "%v\n", cidr)
			if err != nil {
				return err
			}
		}
		return nil
	}
}
