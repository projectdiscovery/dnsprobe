package runner

import (
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
)

type Options struct {
	Resolvers    string
	Hosts        string
	RequestType  string
	Threads      int
	RateLimit    int
	Retries      int
	OutputFormat string
	OutputFile   string
	Raw          bool
	Silent       bool
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.Resolvers, "s", "", "List of resolvers")
	flag.StringVar(&options.Hosts, "l", "", "List of dns domains")
	flag.StringVar(&options.RequestType, "r", "A", "Request Type A, NS, CNAME, SOA, PTR, MX, TXT, AAAA")
	flag.IntVar(&options.Threads, "t", 250, "Number of concurrent requests to make")
	flag.IntVar(&options.Retries, "c", 1, "Max dns retries")
	flag.IntVar(&options.RateLimit, "rate-limit", 1000, "Max Requests/second")
	flag.StringVar(&options.OutputFormat, "f", "simple", "Output type: ip, domain, response, simple (domain + ip), full (domain + response), json (domain + raw response)")
	flag.StringVar(&options.OutputFile, "o", "", "Output file")
	flag.BoolVar(&options.Raw, "raw", false, "Operates like dig")
	flag.BoolVar(&options.Silent, "silent", false, "Silent output")

	flag.Parse()

	// Read the inputs and configure the logging
	options.configureOutput()

	showBanner()

	if options.Version {
		gologger.Infof("Current Version: %s\n", Version)
		os.Exit(0)
	}

	options.validateOptions()

	return options
}

func (options *Options) validateOptions() {

}

// configureOutput configures the output on the screen
func (options *Options) configureOutput() {
	// If the user desires verbose output, show verbose output
	if options.Verbose {
		gologger.MaxLevel = gologger.Verbose
	}
	if options.Debug {
		gologger.MaxLevel = gologger.Debug
	}
	if options.NoColor {
		gologger.UseColors = false
	}
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
