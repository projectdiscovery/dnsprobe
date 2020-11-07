package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"github.com/remeh/sizedwaitgroup"
)

type JsonLine struct {
	Domain   string
	Response string
	IP       string
}

// Runner is a client for running the enumeration process.
type Runner struct {
	options *Options
	dnsx    *dnsx.DNSX
}

func New(options *Options) (*Runner, error) {
	dnsxOptions := dnsx.DefaultOptions
	dnsxOptions.MaxRetries = options.Retries

	if options.Resolvers != "" {
		rs, err := linesInFile(options.Resolvers)
		if err != nil {
			gologger.Fatalf("%s\n", err)
		}
		dnsxOptions.BaseResolvers = append(dnsxOptions.BaseResolvers, rs...)
	}

	questionType, err := dnsx.StringToRequestType(options.RequestType)
	if err != nil {
		return nil, err
	}

	dnsxOptions.QuestionType = questionType
	dnsX, err := dnsx.New(dnsxOptions)
	if err != nil {
		return nil, err
	}

	return &Runner{options: options, dnsx: dnsX}, nil
}

func (r *Runner) Run() error {
	wg := sizedwaitgroup.New(r.options.Threads)
	var wgwriter sync.WaitGroup

	// process file if specified
	var f *os.File
	stat, _ := os.Stdin.Stat()
	if r.options.Hosts != "" {
		var err error
		f, err = os.OpenFile(r.options.Hosts, os.O_RDONLY, os.ModePerm)
		if err != nil {
			return err
		}
		defer f.Close()
	} else if (stat.Mode() & os.ModeCharDevice) == 0 {
		f = os.Stdin
	} else {
		return fmt.Errorf("hosts file or stdin not provided")
	}

	// setup output
	var foutput *os.File
	if r.options.OutputFile != "" {
		var err error
		foutput, err = os.OpenFile(r.options.Hosts, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
		if err != nil {
			return err
		}
	} else {
		foutput = os.Stdout
	}
	defer foutput.Close()

	// writer worker
	wgwriter.Add(1)
	writequeue := make(chan string)
	go func() {
		defer wgwriter.Done()

		// uses a buffer to write to file
		if r.options.OutputFile != "" {
			w := bufio.NewWriter(foutput)
			defer w.Flush()

			for item := range writequeue {
				w.WriteString(item)
			}
			return
		}

		// otherwise writes sequentially to stdout
		for item := range writequeue {
			fmt.Fprintf(foutput, "%s", item)
		}
	}()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		wg.Add()

		go func(domain string) {
			defer wg.Done()

			if isURL(domain) {
				domain = extractDomain(domain)
			}

			if rs, rawResp, err := r.dnsx.LookupRaw(domain); err == nil {
				if r.options.Raw {
					writequeue <- "\n" + rawResp
					return
				}
				for _, rr := range rs {
					tokens := strings.Split(rr, "\t")
					ip := tokens[len(tokens)-1]
					switch r.options.OutputFormat {
					case "ip":
						writequeue <- fmt.Sprintln(ip)
					case "domain":
						writequeue <- fmt.Sprintln(domain)
					case "simple":
						writequeue <- fmt.Sprintf("%s %s\n", domain, ip)
					case "response":
						writequeue <- fmt.Sprintln(r)
					case "full":
						writequeue <- fmt.Sprintf("%s %s\n", domain, rr)
					case "json":
						jsonl := JsonLine{Domain: domain, Response: rr, IP: ip}
						if jsonls, err := json.Marshal(jsonl); err == nil {
							writequeue <- fmt.Sprintln(string(jsonls))
						}
					}
				}
			}
		}(sc.Text())

	}
	if err := sc.Err(); err != nil {
		return err
	}

	wg.Wait()
	close(writequeue)
	wgwriter.Wait()

	return nil
}

func (r *Runner) Close() {

}
