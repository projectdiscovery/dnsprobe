package runner

import (
	"strings"

	"github.com/rs/xid"
)

func (r *Runner) IsWildcard(host string) (bool, map[string]struct{}) {
	orig := make(map[string]struct{})
	wildcards := make(map[string]struct{})

	subdomainPart := strings.TrimSuffix(host, "."+r.options.Domain)
	subdomainTokens := strings.Split(subdomainPart, ".")

	// Build an array by preallocating a slice of a length
	// and create the wildcard generation prefix.
	// We use a rand prefix at the beginning like %rand%.domain.tld
	// A permutation is generated for each level of the subdomain.
	var hosts []string
	hosts = append(hosts, host)
	hosts = append(hosts, xid.New().String()+"."+r.options.Domain)

	for i := 0; i < len(subdomainTokens); i++ {
		newhost := xid.New().String() + "." + strings.Join(subdomainTokens[i:], ".") + "." + r.options.Domain
		hosts = append(hosts, newhost)
	}

	// Iterate over all the hosts generated for rand.
	for _, h := range hosts {
		in, err := r.dnsx.QueryOne(h)
		if err != nil {
			continue
		}

		// Get all the records and add them to the wildcard map
		for _, A := range in.A {
			if host == h {
				orig[A] = struct{}{}
				continue
			}

			if _, ok := wildcards[A]; !ok {
				wildcards[A] = struct{}{}
			}
		}
	}

	// check if original ip are among wildcards
	for a := range orig {
		if _, ok := wildcards[a]; ok {
			return true, wildcards
		}
	}

	return false, wildcards
}
