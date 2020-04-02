package dnsprobe

import (
	"net"

	miekdns "github.com/miekg/dns"
	dns "github.com/projectdiscovery/retryabledns"
)

// DnsProbe is structure to perform dns lookups
type DnsProbe struct {
	dnsClient    *dns.Client
	questionType uint16
}

// Options contains configuration options
type Options struct {
	BaseResolvers []string
	MaxRetries    int
	QuestionType  uint16
}

// DefaultOptions contains the default configuration options
var DefaultOptions = Options{
	BaseResolvers: DefaultResolvers,
	MaxRetries:    5,
	QuestionType:  miekdns.TypeA,
}

// DefaultResolvers contains the list of resolvers known to be trusted.
var DefaultResolvers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// New creates a dns resolver
func New(options Options) (*DnsProbe, error) {
	dnsClient, err := dns.New(options.BaseResolvers, options.MaxRetries)
	if err != nil {
		return nil, err
	}

	return &DnsProbe{dnsClient: dnsClient, questionType: options.QuestionType}, nil
}

// Lookup performs a DNS A question and returns corresponding IPs
func (d *DnsProbe) Lookup(hostname string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []string{hostname}, nil
	}

	results, err := d.dnsClient.Resolve(hostname)
	if err != nil {
		return nil, err
	}

	return results.IPs, nil
}

// LookupRaw performs a DNS question of a specified type and returns raw responses
func (d *DnsProbe) LookupRaw(hostname string) ([]string, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return []string{hostname}, nil
	}

	return d.dnsClient.ResolveRaw(hostname, d.questionType)
}
