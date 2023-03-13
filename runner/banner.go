package runner

import "github.com/projectdiscovery/gologger"

const banner = `
   ___   _____  __              
  / _ | / __/ |/ /_ _  ___ ____ 
 / __ |_\ \/    /  ' \/ _  / _ \
/_/ |_/___/_/|_/_/_/_/\_,_/ .__/
                         /_/    v1.0.2  
`

// Version is the current version of mapcidr
const Version = `v1.0.2`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Print().Msgf("%s\n", banner)
	gologger.Print().Msgf("\t\tprojectdiscovery.io\n\n")
}
