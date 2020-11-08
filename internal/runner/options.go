package runner

import (
	"flag"
	"os"

	"github.com/projectdiscovery/gologger"
)

type Options struct {
	Resolvers    string
	Hosts        string
	Threads      int
	RateLimit    int
	Retries      int
	OutputFormat string
	OutputFile   string
	Raw          bool
	Silent       bool
	Verbose      bool
	Version      bool
	Response     bool
	ResponseOnly bool
	A            bool
	AAAA         bool
	NS           bool
	CNAME        bool
	PTR          bool
	MX           bool
	SOA          bool
	TXT          bool
	JSON         bool
}

// ParseOptions parses the command line options for application
func ParseOptions() *Options {
	options := &Options{}
	flag.StringVar(&options.Resolvers, "r", "", "List of resolvers (file or command separated)")
	flag.StringVar(&options.Hosts, "l", "", "List of dns domains")
	flag.IntVar(&options.Threads, "t", 250, "Number of concurrent requests to make")
	flag.IntVar(&options.Retries, "c", 1, "Max dns retries")
	flag.IntVar(&options.RateLimit, "rate-limit", -1, "Max Requests/second")
	flag.StringVar(&options.OutputFormat, "f", "", "Output type: ip, domain, response, simple (domain + ip), full (domain + response), json (domain + raw response)")
	flag.StringVar(&options.OutputFile, "o", "", "Output file")
	flag.BoolVar(&options.Raw, "raw", false, "Operates like dig")
	flag.BoolVar(&options.Silent, "silent", false, "Silent output")
	flag.BoolVar(&options.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&options.Version, "version", false, "Version")
	flag.BoolVar(&options.Response, "resp", false, "Print response value")
	flag.BoolVar(&options.ResponseOnly, "resp-only", false, "Print response only value")
	flag.BoolVar(&options.A, "A", false, "A")
	flag.BoolVar(&options.AAAA, "AAAA", false, "AAAA")
	flag.BoolVar(&options.NS, "NS", false, "NS")
	flag.BoolVar(&options.CNAME, "CNAME", false, "CNAME")
	flag.BoolVar(&options.PTR, "PTR", false, "PTR")
	flag.BoolVar(&options.MX, "MX", false, "MX")
	flag.BoolVar(&options.SOA, "SOA", false, "SOA")
	flag.BoolVar(&options.TXT, "TXT", false, "TXT")
	flag.BoolVar(&options.JSON, "json", false, "JSON output")

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
	if options.Silent {
		gologger.MaxLevel = gologger.Silent
	}
}
