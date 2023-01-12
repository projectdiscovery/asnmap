package asnmap

import (
	"regexp"
	"strconv"
	"strings"

	iputil "github.com/projectdiscovery/utils/ip"
)

type InputType uint8

const (
	ASN InputType = iota
	IP
	Org
	Domain
	Unknown
)

var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9-]+(\.[a-z0-9-]+)+\.?$`)

// checkIfASN checks if the given input is ASN or not,
// its possible to have an org name starting with AS/as prefix.
func checkIfASN(input string) bool {
	_, err := strconv.Atoi(input[2:])
	return strings.HasPrefix(strings.ToUpper(input), "AS") && err == nil
}

func IdentifyInput(input string) InputType {
	switch {
	case iputil.IsIP(input):
		return IP
	case checkIfASN(input):
		return ASN
	case domainRegex.MatchString(input):
		return Domain
	default:
		return Org
	}
}
