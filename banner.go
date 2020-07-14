package main

import "github.com/projectdiscovery/gologger"

const banner = `
       __                            __       
  ____/ /___  _________  _________  / /_  ___ 
 / __  / __ \/ ___/ __ \/ ___/ __ \/ __ \/ _ \
/ /_/ / / / (__  ) /_/ / /  / /_/ / /_/ /  __/
\__,_/_/ /_/____/ .___/_/   \____/_.___/\___/ 
               /_/                            										  
`

// Version is the current version of dnsprobe
const Version = `1.0.3`

// showBanner is used to show the banner to the user
func showBanner() {
	gologger.Printf("%s\n", banner)
	gologger.Printf("\t\tprojectdiscovery.io\n\n")

	gologger.Labelf("Use with caution. You are responsible for your actions\n")
	gologger.Labelf("Developers assume no liability and are not responsible for any misuse or damage.\n")
}
