package asnmap

import (
	"github.com/stretchr/testify/require"

	"testing"
)

func TestGetASNFromIP(t *testing.T) {
	client, err := NewClient()
	require.Nil(t, err)

	tt := []struct {
		name   string
		ip     string
		result []*Response
	}{
		{"found", "100.19.12.21", []*Response{{FirstIp: "", LastIp: "", Input: "100.19.12.21", ASN: 701, Country: "US", Org: "uunet"}}},
		{"not found", "255.100.100.100", []*Response{}},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			i, err := client.GetData(tc.ip)
			require.Nil(t, err)
			// // Expecting true from comparision
			for _, result := range tc.result {
				x := compareResponse(i, result)
				require.True(t, x)
			}
		})
	}
}

func TestGetIPFromASN(t *testing.T) {
	client, err := NewClient()
	require.Nil(t, err)

	tt := []struct {
		name   string
		asn    string
		result []*Response
	}{
		{
			"zero match", "1123", []*Response{},
		},
		{
			"single match", "14421", []*Response{{
				FirstIp: "216.101.17.0",
				LastIp:  "216.101.17.255",
				Input:   "14421",
				ASN:     14421,
				Country: "US",
				Org:     "theravance",
			}},
		},
		{
			"multi match", "7712", []*Response{
				{
					FirstIp: "118.67.200.0",
					LastIp:  "118.67.202.255",
					Input:   "7712",
					ASN:     7712,
					Country: "KH",
					Org:     "sabay sabay digital cambodia",
				},
				{
					FirstIp: "118.67.203.0",
					LastIp:  "118.67.207.255",
					Input:   "7712",
					ASN:     7712,
					Country: "KH",
					Org:     "sabay sabay digital cambodia",
				},
				{
					FirstIp: "2405:aa00::",
					LastIp:  "2405:aa00:ffff:ffff:ffff:ffff:ffff:ffff",
					Input:   "7712",
					ASN:     7712,
					Country: "KH",
					Org:     "sabay sabay digital cambodia",
				}},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			i, err := client.GetData(tc.asn)
			require.Nil(t, err)
			for _, result := range tc.result {
				x := compareResponse(i, result)
				require.True(t, x)
			}
		})
	}
}

func TestGetASNFromOrg(t *testing.T) {
	t.Skip("asnmap-server returns null for this query, skipping")
	client, err := NewClient()
	require.Nil(t, err)

	tt := []struct {
		name     string
		org      string
		err      bool
		expected []*Response
	}{
		{"not found", "RANDOM_TEXT", true, []*Response{}},
		// Todo: excluding - ref: https://github.com/projectdiscovery/asnmap-server/issues/43
		// {"regex match", "PPLINKNET*", false, []*Response{
		// 	{
		// 		FirstIp: "45.239.52.0",
		// 		LastIp:  "45.239.55.255",
		// 		Input:   "PPLINKNET",
		// 		ASN:     268353,
		// 		Country: "BR",
		// 		Org:     "PPLINKNET SERVICOS DE COMUNICACAO LTDA - ME"},
		// 	{
		// 		FirstIp: "2804:4fd8::",
		// 		LastIp:  "2804:4fd8:ffff:ffff:ffff:ffff:ffff:ffff",
		// 		Input:   "PPLINKNET",
		// 		ASN:     268353,
		// 		Country: "BR",
		// 		Org:     "PPLINKNET SERVICOS DE COMUNICACAO LTDA - ME"},
		// }},
		{"exact match", "PPLINKNET", false, []*Response{}},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			i, err := client.GetData(tc.org)
			if tc.err {
				require.NotNil(t, err)
				return
			} else {
				require.Nil(t, err)
			}
			// // Expecting true from comparision
			for _, result := range tc.expected {
				x := compareResponse(i, result)
				require.True(t, x)
			}
		})
	}
}

// compareResponse compares ASN & ORG against given domain with expected output's ASN & ORG
// Have excluded IPs for now as they might change in future.
func compareResponse(respA []*Response, respB *Response) bool {
	for _, r := range respA {
		if r.Equal(*respB) {
			return true
		}
	}
	return false
}
