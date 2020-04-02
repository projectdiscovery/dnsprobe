package dnsprobe

import "github.com/miekg/dns"

// StringToRequestType conversion helper
func StringToRequestType(tp string) uint16 {
	switch tp {
	case "A":
		return dns.TypeA
	case "NS":
		return dns.TypeNS
	case "CNAME":
		return dns.TypeCNAME
	case "SOA":
		return dns.TypeSOA
	case "PTR":
		return dns.TypePTR
	case "MX":
		return dns.TypeMX
	case "TXT":
		return dns.TypeTXT
	case "AAAA":
		return dns.TypeAAAA
	default:
		return dns.TypeNone
	}
}
