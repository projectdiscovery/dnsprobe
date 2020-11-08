package runner

import (
	"bufio"
	"fmt"
	"os"
	"sync"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/gologger"
	"go.uber.org/ratelimit"
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
	limiter          ratelimit.Limiter
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

	var questionTypes []uint16
	if options.A {
		questionTypes = append(questionTypes, dns.TypeA)
	}
	if options.AAAA {
		questionTypes = append(questionTypes, dns.TypeAAAA)
	}
	if options.CNAME {
		questionTypes = append(questionTypes, dns.TypeCNAME)
	}
	if options.PTR {
		questionTypes = append(questionTypes, dns.TypePTR)
	}
	if options.SOA {
		questionTypes = append(questionTypes, dns.TypeSOA)
	}
	if options.TXT {
		questionTypes = append(questionTypes, dns.TypeTXT)
	}
	if options.MX {
		questionTypes = append(questionTypes, dns.TypeMX)
	}
	if options.NS {
		questionTypes = append(questionTypes, dns.TypeNS)
	}
	if len(questionTypes) == 0 {
		questionTypes = append(questionTypes, dns.TypeA)
	}
	dnsxOptions.QuestionTypes = questionTypes

	dnsX, err := dnsx.New(dnsxOptions)
	if err != nil {
		return nil, err
	}

	limiter := ratelimit.NewUnlimited()
	if options.RateLimit > 0 {
		limiter = ratelimit.New(options.RateLimit)
	}

	r := Runner{
		options:          options,
		dnsx:             dnsX,
		wgoutputworker:   &sync.WaitGroup{},
		wgresolveworkers: &sync.WaitGroup{},
		workerchan:       make(chan string),
		outputchan:       make(chan string),
		limiter:          limiter,
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
			w.WriteString(item + "\n")
		} else {
			// otherwise writes sequentially to stdout
			fmt.Fprintf(foutput, "%s\n", item)
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
		r.limiter.Take()
		if dnsData, err := r.dnsx.QueryMultiple(domain); err == nil {
			if r.options.Raw {
				r.outputchan <- dnsData.Raw
				continue
			}
			if r.options.JSON {
				jsons, _ := dnsData.JSON()
				r.outputchan <- jsons
				continue
			}
			if r.options.A {
				r.outputRecordType(domain, dnsData.A)
			}
			if r.options.AAAA {
				r.outputRecordType(domain, dnsData.AAAA)
			}
			if r.options.CNAME {
				r.outputRecordType(domain, dnsData.CNAME)
			}
			if r.options.PTR {
				r.outputRecordType(domain, dnsData.PTR)
			}
			if r.options.MX {
				r.outputRecordType(domain, dnsData.MX)
			}
			if r.options.NS {
				r.outputRecordType(domain, dnsData.NS)
			}
			if r.options.SOA {
				r.outputRecordType(domain, dnsData.SOA)
			}
			if r.options.TXT {
				r.outputRecordType(domain, dnsData.TXT)
			}
		}
	}
}

func (r *Runner) outputRecordType(domain string, items []string) {
	for _, item := range items {
		if r.options.ResponseOnly {
			r.outputchan <- item
		} else if r.options.Response {
			r.outputchan <- domain + " [" + item + "]"
		} else {
			// just prints out the domain if it has a record type and exit
			r.outputchan <- domain
			break
		}
	}
}

func (r *Runner) Close() {

}
