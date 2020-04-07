package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	dnsprobe "github.com/projectdiscovery/dnsprobe/lib"
	"github.com/remeh/sizedwaitgroup"
)

var (
	resolvers    = flag.String("s", "", "List of resolvers")
	hosts        = flag.String("l", "", "List of dns domains")
	requestType  = flag.String("r", "A", "Request Type A, NS, CNAME, SOA, PTR, MX, TXT, AAAA")
	concurrency  = flag.Int("t", 250, "Number of concurrent requests to make")
	retries      = flag.Int("c", 1, "Max dns retries")
	outputFormat = flag.String("f", "full", "Output type: ip, domain, response, simple (domain + ip), full (domain + response), json (domain + raw response)")
	outputFile   = flag.String("o", "", "Output file")
)

type JsonLine struct {
	Domain   string
	Response string
	IP       string
}

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

	questionType, err := dnsprobe.StringToRequestType(*requestType)
	if err != nil {
		log.Fatalf("Error: %s", err)
	}

	options.QuestionType = questionType

	var dnsProbe *dnsprobe.DnsProbe
	dnsProbe, err = dnsprobe.New(options)
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
			log.Fatalf("open file error: %s", err)
			return
		}
		defer f.Close()
	} else if (stat.Mode() & os.ModeCharDevice) == 0 {
		f = os.Stdin
	} else {
		log.Fatalf("hosts file or stdin not provided")
	}

	// setup output
	var foutput *os.File
	if *outputFile != "" {
		foutput, err = os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err != nil {
			log.Fatalf("open file error: %s", err)
		}
	} else {
		foutput = os.Stdout
	}
	defer foutput.Close()

	w := bufio.NewWriter(foutput)
	defer w.Flush()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		wg.Add()

		go func(domain string) {
			defer wg.Done()

			if rs, err := dnsProbe.LookupRaw(domain); err == nil {
				for _, r := range rs {
					tokens := strings.Split(r, "\t")
					ip := tokens[len(tokens)-1]
					switch *outputFormat {
					case "ip":
						w.WriteString(fmt.Sprintln(ip))
					case "domain":
						w.WriteString(fmt.Sprintln(domain))
					case "simple":
						w.WriteString(fmt.Sprintf("%s %s\n", domain, ip))
					case "response":
						w.WriteString(fmt.Sprintln(r))
					case "full":
						w.WriteString(fmt.Sprintf("%s %s\n", domain, r))
					case "json":
						jsonl := JsonLine{Domain: domain, Response: r, IP: ip}
						if jsonls, err := json.Marshal(jsonl); err == nil {
							w.WriteString(fmt.Sprintln(string(jsonls)))
						}
					}

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
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	return result, nil
}
