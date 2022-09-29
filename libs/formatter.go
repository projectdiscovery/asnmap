package asnmap

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// To model json & csv formatted output
type Result struct {
	Timestamp  string   `json:"timestamp,omitempty" csv:"timestamp"`
	Input      string   `json:"input" csv:"input"`
	ASN        string   `json:"as_number" csv:"as_number"`
	ASN_org    string   `json:"as_name" csv:"as_name"`
	AS_country string   `json:"as_country" csv:"as_country"`
	AS_range   []string `json:"as_range" csv:"as_range"`
}

// To model http response from server
type Response struct {
	FirstIp string
	LastIp  string
	Input   string
	ASN     int
	Country string
	Org     string
}

// attachPrefix func attaches 'AS' prefix to ASN numbers
func attachPrefix(input string) string {
	inp := input
	if _, err := strconv.Atoi(input); err == nil {
		inp = "AS" + input
	}
	return inp
}

func convertIPsToStringSlice(ips []*net.IPNet) []string {
	var res []string
	for _, ip := range ips {
		res = append(res, ip.String())
	}
	return res
}

func intializeResult(resp Response) Result {
	result := Result{}
	result.Timestamp = time.Now().Local().String()
	result.Input = attachPrefix(resp.Input)
	result.ASN = attachPrefix(strconv.Itoa(resp.ASN))
	result.ASN_org = resp.Org
	result.AS_country = resp.Country
	result.AS_range = convertIPsToStringSlice(GetCIDR([]Response{resp}))
	return result
}

func prepareFormattedJSON(input Response) []byte {
	result := intializeResult(input)
	output, err := json.Marshal(result)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	return output
}

func prepareFormattedCSV(input Response) []string {
	var record []string
	result := intializeResult(input)
	record = append(record, result.Timestamp, result.Input, result.ASN, result.ASN_org, result.AS_country, strings.Join(result.AS_range, ","))
	return record
}

func GetFormattedDataInJson(output []Response) []byte {
	var jsonOutput []byte
	for _, res := range output {
		jsonOutput = append(jsonOutput, prepareFormattedJSON(res)...)
	}
	return jsonOutput
}

func GetFormattedDataInCSV(output []Response) [][]string {
	records := [][]string{}

	for _, res := range output {
		record := prepareFormattedCSV(res)
		records = append(records, record)
	}

	return records
}
