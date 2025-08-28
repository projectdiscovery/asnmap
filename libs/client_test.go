package asnmap

import (
	"github.com/stretchr/testify/require"

	"testing"
)

func TestGetASNFromIP(t *testing.T) {
	client, err := NewClient()
	require.Nil(t, err)

	t.Run("found", func(t *testing.T) {
		ip := "100.19.12.21"
		expectedResult := []*Response{{FirstIp: "", LastIp: "", Input: "100.19.12.21", ASN: 701, Country: "US", Org: "uunet"}}
		i, err := client.GetData(ip)
		require.Nil(t, err)
		for _, result := range expectedResult {
			x := compareResponse(i, result)
			require.True(t, x)
		}
	})

	t.Run("not found", func(t *testing.T) {
		ip := "255.100.100.100"
		expectedErrMsg := "bad request: {\"error\":\"no results found\"}"
		_, err := client.GetData(ip)
		require.NotNil(t, err)
		require.EqualError(t, err, expectedErrMsg)
	})
}

func TestGetIPFromASN(t *testing.T) {
	client, err := NewClient()
	require.Nil(t, err)

	t.Run("zero match", func(t *testing.T) {
		expectedErrMsg := "bad request: {\"error\":\"no results found\"}"
		_, err := client.GetData("1123")
		require.NotNil(t, err)
		require.EqualError(t, err, expectedErrMsg)
	})

	t.Run("single match", func(t *testing.T) {
		result := []*Response{{
			FirstIp: "216.101.17.0",
			LastIp:  "216.101.17.255",
			Input:   "14421",
			ASN:     14421,
			Country: "US",
			Org:     "theravance",
		}}
		i, err := client.GetData("14421")
		require.Nil(t, err)
		for _, expected := range result {
			x := compareResponse(i, expected)
			require.True(t, x)
		}
	})

	t.Run("multi match", func(t *testing.T) {
		result := []*Response{
			{
				FirstIp: "118.67.200.0",
				LastIp:  "118.67.203.255",
				Input:   "7712",
				ASN:     7712,
				Country: "KH",
				Org:     "cne-as-ap cambodian network exchange co., ltd.",
			},
			{
				FirstIp: "118.67.200.0",
				LastIp:  "118.67.207.255",
				Input:   "7712",
				ASN:     7712,
				Country: "KH",
				Org:     "cne-as-ap cambodian network exchange co., ltd.",
			},
		}
		i, err := client.GetData("7712")
		require.Nil(t, err)
		for _, expected := range result {
			x := compareResponse(i, expected)
			require.True(t, x)
		}
	})
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
