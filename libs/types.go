package asnmap

import (
	"net"
	"regexp"
	"strconv"
	"strings"
)

type ASN string

type IP string

type Org string

type Domain string

var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9-]+(\.[a-z0-9-]+)+\.?$`)

/*
checkIfASN checks if the given input is ASN or not, 
its possible to have an org name starting with AS/as prefix.
*/
func checkIfASN(input string) bool {
	_, err := strconv.Atoi(input[2:])
	return strings.HasPrefix(strings.ToUpper(input), "AS") && err == nil
}

func IdentifyInput(input string) interface{} {
	var ret interface{}
	if v := net.ParseIP(input); v != nil {
		ret = IP(input)
	} else if checkIfASN(input) {
		ret = ASN(input[2:])
	} else if domainRegex.MatchString(input) {
		ret = Domain(input)
	} else {
		ret = Org(input)
	}

	return ret
}
