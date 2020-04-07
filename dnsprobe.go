package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	dnsprobe "github.com/projectdiscovery/dnsprobe/lib"
	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
)

var (
	resolvers    = flag.String("s", "", "List of resolvers")
	hosts        = flag.String("l", "", "List of dns domains")
	requestType  = flag.String("r", "A", "Request Type A, NS, CNAME, SOA, PTR, MX, TXT, AAAA")
	concurrency  = flag.Int("t", 250, "Number of concurrent requests to make")
	retries      = flag.Int("c", 1, "Max dns retries")
	outputFormat = flag.String("f", "simple", "Output type: ip, domain, response, simple (domain + ip), full (domain + response), json (domain + raw response)")
	outputFile   = flag.String("o", "", "Output file")
)

type JsonLine struct {
	Domain   string
	Response string
	IP       string
}

func main() {

	// show banner
	showBanner()

	flag.Parse()

	options := dnsprobe.DefaultOptions
	options.MaxRetries = *retries

	if *resolvers != "" {
		rs, err := linesInFile(*resolvers)
		if err != nil {
			gologger.Fatalf("%s\n", err)
		}
		options.BaseResolvers = append(options.BaseResolvers, rs...)
	}

	questionType, err := dnsprobe.StringToRequestType(*requestType)
	if err != nil {
		gologger.Fatalf("%s\n", err)
	}

	options.QuestionType = questionType

	var dnsProbe *dnsprobe.DnsProbe
	dnsProbe, err = dnsprobe.New(options)
	if err != nil {
		gologger.Fatalf("%s\n", err)
	}

	wg := sizedwaitgroup.New(*concurrency)
	var wgwriter sync.WaitGroup

	// process file if specified
	var f *os.File
	stat, _ := os.Stdin.Stat()
	// process file if specified
	if *hosts != "" {
		var err error
		f, err = os.OpenFile(*hosts, os.O_RDONLY, os.ModePerm)
		if err != nil {
			gologger.Fatalf("%s\n", err)
			return
		}
		defer f.Close()
	} else if (stat.Mode() & os.ModeCharDevice) == 0 {
		f = os.Stdin
	} else {
		gologger.Fatalf("hosts file or stdin not provided")
	}

	// setup output
	var foutput *os.File
	if *outputFile != "" {
		foutput, err = os.OpenFile(*outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err != nil {
			gologger.Fatalf("%s\n", err)
		}
	} else {
		foutput = os.Stdout
	}
	defer foutput.Close()

	w := bufio.NewWriter(foutput)
	defer w.Flush()

	// writer worker
	wgwriter.Add(1)
	writequeue := make(chan string)
	go func() {
		defer wgwriter.Done()
		for item := range writequeue {
			w.WriteString(item)
		}
	}()

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
						writequeue <- fmt.Sprintln(ip)
					case "domain":
						writequeue <- fmt.Sprintln(domain)
					case "simple":
						writequeue <- fmt.Sprintf("%s %s\n", domain, ip)
					case "response":
						writequeue <- fmt.Sprintln(r)
					case "full":
						writequeue <- fmt.Sprintf("%s %s\n", domain, r)
					case "json":
						jsonl := JsonLine{Domain: domain, Response: r, IP: ip}
						if jsonls, err := json.Marshal(jsonl); err == nil {
							writequeue <- fmt.Sprintln(string(jsonls))
						}
					}

				}
			}
		}(sc.Text())

	}
	if err := sc.Err(); err != nil {
		gologger.Fatalf("%s\n", err)
		return
	}

	wg.Wait()
	close(writequeue)
	wgwriter.Wait()
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
