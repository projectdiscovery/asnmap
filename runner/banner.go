package runner

import (
	"github.com/projectdiscovery/gologger"
	updateutils "github.com/projectdiscovery/utils/update"
)

const banner = `
   ___   _____  __              
  / _ | / __/ |/ /_ _  ___ ____ 
 / __ |_\ \/    /  ' \/ _  / _ \
/_/ |_/___/_/|_/_/_/_/\_,_/ .__/
                         /_/ 
`

// version is the current version of asnmap
const version = `v1.0.4`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}

// GetUpdateCallback returns a callback function that updates asnmap
func GetUpdateCallback() func() {
	return func() {
		showBanner()
		updateutils.GetUpdateToolCallback("asnmap", version)()
	}
}
