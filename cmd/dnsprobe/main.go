package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	dnsprobe "github.com/projectdiscovery/dns-probe"
	"github.com/remeh/sizedwaitgroup"
)

var (
	resolvers   = flag.String("s", "", "List of resolvers")
	hosts       = flag.String("l", "", "List of urls to check for stuff")
	requestType = flag.String("r", "A", "Request Type A, NS, CNAME, SOA, PTR, MX, TXT, AAAA")
	concurrency = flag.Int("t", 250, "Number of concurrent requests to make")
	retries     = flag.Int("c", 1, "Max dns retries")
	verbose     = flag.Bool("v", false, "Output full A response")
)

func main() {
	flag.Parse()

	options := dnsprobe.DefaultOptions
	options.MaxRetries = *retries

	if *resolvers != "" {
		rs, err := linesInFile(*resolvers)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		options.BaseResolvers = append(options.BaseResolvers, rs...)
	}

	options.QuestionType = dnsprobe.StringToRequestType(*requestType)

	dnsProbe, err := dnsprobe.New(options)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	wg := sizedwaitgroup.New(*concurrency)

	// process file if specified
	var f *os.File
	stat, _ := os.Stdin.Stat()
	// process file if specified
	if *hosts != "" {
		var err error
		f, err = os.OpenFile(*hosts, os.O_RDONLY, os.ModePerm)
		if err != nil {
			log.Fatalf("open file error: %v", err)
			return
		}
		defer f.Close()
	} else if (stat.Mode() & os.ModeCharDevice) == 0 {
		f = os.Stdin
	} else {
		log.Fatalf("hosts file or stdin not provided")
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		wg.Add()

		go func(domain string) {
			defer wg.Done()

			if ips, err := dnsProbe.LookupRaw(domain); err == nil {
				for _, ip := range ips {
					if !(*verbose) {
						tokens := strings.Split(ip, "\t")
						ip = tokens[len(tokens)-1]
					}
					fmt.Printf("%s %s\n", domain, ip)
				}
			}
		}(sc.Text())

	}
	if err := sc.Err(); err != nil {
		log.Printf("scan file error: %v", err)
		return
	}

	wg.Wait()
}

func linesInFile(fileName string) ([]string, error) {
	result := []string{}
	f, err := os.Open(fileName)
	if err != nil {
		return result, err
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	return result, nil
}
