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
)

type JsonLine struct {
	Domain   string
	Response string
	IP       string
}

// Runner is a client for running the enumeration process.
type Runner struct {
	options          *Options
	dnsx             *dnsx.DNSX
	wgoutputworker   *sync.WaitGroup
	wgresolveworkers *sync.WaitGroup
	workerchan       chan string
	outputchan       chan string
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

	r := Runner{
		options:          options,
		dnsx:             dnsX,
		wgoutputworker:   &sync.WaitGroup{},
		wgresolveworkers: &sync.WaitGroup{},
		workerchan:       make(chan string),
		outputchan:       make(chan string),
	}

	return &r, nil
}

func (r *Runner) Run() error {
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

	r.startWorkers()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		r.workerchan <- sc.Text()
	}

	close(r.workerchan)

	r.wgresolveworkers.Wait()

	close(r.outputchan)

	r.wgoutputworker.Wait()

	return nil
}

func (r *Runner) HandleOutput() {
	defer r.wgoutputworker.Done()

	// setup output
	var foutput *os.File
	if r.options.OutputFile != "" {
		var err error
		foutput, err = os.Create(r.options.Hosts)
		if err != nil {
			gologger.Fatalf("%s\n", err)
		}
	} else {
		foutput = os.Stdout
	}
	defer foutput.Close()

	var w *bufio.Writer
	if r.options.OutputFile != "" {
		w = bufio.NewWriter(foutput)
		defer w.Flush()
	}

	for item := range r.outputchan {
		if r.options.OutputFile != "" {
			// uses a buffer to write to file
			w.WriteString(item)
		} else {
			// otherwise writes sequentially to stdout
			fmt.Fprintf(foutput, "%s", item)
		}
	}
}

func (r *Runner) startWorkers() {
	// output worker
	r.wgoutputworker.Add(1)
	go r.HandleOutput()

	// resolve workers
	for i := 0; i < r.options.Threads; i++ {
		r.wgresolveworkers.Add(1)
		go r.worker()
	}
}

func (r *Runner) worker() {
	defer r.wgresolveworkers.Done()

	for domain := range r.workerchan {
		if isURL(domain) {
			domain = extractDomain(domain)
		}

		if rs, rawResp, err := r.dnsx.LookupRaw(domain); err == nil {
			if r.options.Raw {
				r.outputchan <- "\n" + rawResp
				continue
			}
			for _, rr := range rs {
				tokens := strings.Split(rr, "\t")
				ip := tokens[len(tokens)-1]
				switch r.options.OutputFormat {
				case "ip":
					r.outputchan <- fmt.Sprintln(ip)
				case "domain":
					r.outputchan <- fmt.Sprintln(domain)
				case "simple":
					r.outputchan <- fmt.Sprintf("%s %s\n", domain, ip)
				case "response":
					r.outputchan <- fmt.Sprintln(r)
				case "full":
					r.outputchan <- fmt.Sprintf("%s %s\n", domain, rr)
				case "json":
					jsonl := JsonLine{Domain: domain, Response: rr, IP: ip}
					if jsonls, err := json.Marshal(jsonl); err == nil {
						r.outputchan <- fmt.Sprintln(string(jsonls))
					}
				default:
					r.outputchan <- fmt.Sprintln(ip)
				}
			}
		}
	}
}

func (r *Runner) Close() {

}
