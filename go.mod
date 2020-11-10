module github.com/projectdiscovery/dnsx

go 1.14

replace github.com/projectdiscovery/retryabledns => /home/marco/go/src/github.com/projectdiscovery/retryabledns

require (
	github.com/miekg/dns v1.1.35
	github.com/projectdiscovery/gologger v1.0.1
	github.com/projectdiscovery/hmap v0.0.0-20201026185329-db41b5717bcb
	github.com/projectdiscovery/retryabledns v1.0.5-0.20201110214149-30d487cf6b77
	go.uber.org/ratelimit v0.1.0
)
