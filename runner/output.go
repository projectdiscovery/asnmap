package runner

import (
	"encoding/csv"
	"fmt"
	"net"
	"strings"

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

// filterIPv6
// - DisplayIPv6==true => returns IPv6 + IPv4
// - DisplayIPv6==false => returns IPv4
func (r *Runner) filterIPv6(ipsnet []*net.IPNet) []*net.IPNet {
	if r.options.DisplayIPv6 {
		// ipv4 + ipv6
		return ipsnet
	}

	// only ipv4
	var filteredIpsNet []*net.IPNet
	for _, ipnet := range ipsnet {
		value := ipnet.String()
		// trim net suffix
		if idx := strings.Index(value, "/"); idx >= 0 {
			value = value[:idx]
		}
		if iputil.IsIPv4(value) {
			filteredIpsNet = append(filteredIpsNet, ipnet)
		}
	}
	return filteredIpsNet
}

// writeOutput either to file or to stdout
func (r *Runner) writeOutput(output []*asnmap.Response) error {
	if r.options.OnResult != nil {
		r.options.OnResult(output)
	}
	// empty output is ignored
	if r.options.Output == nil {
		return nil
	}
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
