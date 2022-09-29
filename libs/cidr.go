package asnmap

import (
	"net"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
)

func GetCIDR(output []Response) []*net.IPNet {
	var cidrs []*net.IPNet
	for _, res := range output {
		cidr, err := mapcidr.GetCIDRFromIPRange(net.ParseIP(res.FirstIp), net.ParseIP(res.LastIp))
		if err != nil {
			gologger.Fatal().Msg(err.Error())
		}
		cidrs = append(cidrs, cidr...)
	}
	return cidrs
}
