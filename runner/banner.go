package runner

import (
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/utils/auth/pdcp"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `
   ___   _____  __              
  / _ | / __/ |/ /_ _  ___ ____ 
 / __ |_\ \/    /  ' \/ _  / _ \
/_/ |_/___/_/|_/_/_/_/\_,_/ .__/
                         /_/ 
`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates asnmap
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("asnmap", asnmap.Version)()
	}
}

// AuthWithPDCP is used to authenticate with PDCP
func AuthWithPDCP() {
	showBanner()
	pdcp.CheckNValidateCredentials("asnmap")
}
