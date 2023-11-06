package runner

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
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

func (r *Runner) writeToJson(results []*asnmap.Result) error {
	for _, result := range results {
		record, err := json.Marshal(result)
		if err != nil {
			return err
		}
		record = append(record, '\n')
		if _, err := io.Copy(r.options.Output, bytes.NewReader(record)); err != nil {
			return err
		}
	}
	return nil
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
		results, err := asnmap.MapToResults(output)
		if err != nil {
			return err
		}

		return r.writeToJson(results)
	case r.options.DisplayInCSV:
		results, err := asnmap.MapToResults(output)
		if err != nil {
			return err
		}
		records := [][]string{}
		for _, result := range results {
			record := []string{result.Timestamp, result.Input, result.ASN, result.ASN_org, result.AS_country, strings.Join(result.AS_range, ",")}
			records = append(records, record)
		}
		return r.writeToCsv(records)
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
