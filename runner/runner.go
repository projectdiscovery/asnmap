package runner

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"strings"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type Runner struct {
	options *Options
	hm      *hybrid.HybridMap
	client  *asnmap.Client
}

func New(options *Options) (*Runner, error) {
	client, err := asnmap.NewClient()
	if err != nil {
		return nil, err
	}
	return &Runner{options: options, client: client}, nil
}

func (r *Runner) Close() error {
	if r.hm != nil {
		err := r.hm.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *Runner) Run() error {
	if len(r.options.Proxy) > 0 {
		if proxyURL, err := r.client.SetProxy(r.options.Proxy); err != nil {
			return fmt.Errorf("Could not set proxy: %s", err)
		} else {
			gologger.Info().Msgf("Using %s proxy %s", proxyURL.Scheme, proxyURL.String())
		}
	}

	if r.options.DisplayInCSV {
		if r.options.OutputFile != "" {
			file, err := os.Create(r.options.OutputFile)
			if err != nil {
				return err
			}
			r.options.Output = file
		}
		w := csv.NewWriter(r.options.Output)
		w.Comma = '|'

		for _, record := range csvHeaders {
			if err := w.Write(record); err != nil {
				return err
			}
		}
		w.Flush()
	}

	if err := r.prepareInput(); err != nil {
		return err
	}

	return r.process()
}

// Process Function makes request to client returns response
func (r *Runner) process() error {
	var errProcess error
	r.hm.Scan(func(key, _ []byte) error {
		item := string(key)
		switch asnmap.IdentifyInput(item) {
		case asnmap.Domain:
			resolvedIps, err := asnmap.ResolveDomain(item, r.options.Resolvers...)
			if err != nil {
				gologger.Verbose().Msgf("could not resolve '%s': %v", item, err)
				return nil
			}

			if len(resolvedIps) == 0 {
				gologger.Verbose().Msgf("No records found for %v", item)
				return nil
			}

			var responses []asnmap.Response
			for _, resolvedIp := range resolvedIps {
				ls, err := r.client.GetDataWithCustomInput(resolvedIp, item)
				if err != nil {
					errProcess = err
					break
				}

				for _, l := range ls {
					if !sliceutil.Contains(responses, *l) {
						responses = append(responses, *l)
					}
				}
			}

			for _, response := range responses {
				if err := r.writeOutput([]*asnmap.Response{&response}); err != nil {
					errProcess = err
					return err
				}
			}

		default:
			ls, err := r.client.GetData(item)
			if err != nil {
				errProcess = err
				return err
			}
			if len(ls) == 0 {
				gologger.Verbose().Msgf("No records found for %v", item)
				return nil
			}
			if err := r.writeOutput(ls); err != nil {
				errProcess = err
				return err
			}
		}

		return nil
	})
	return errProcess
}

func (r *Runner) setItem(v string) {
	item := strings.TrimSpace(v)
	if item != "" {
		_ = r.hm.Set(item, nil)
	}
}

func (r *Runner) prepareInput() error {
	var err error
	r.hm, err = hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return err
	}
	if fileutil.HasStdin() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			r.setItem(scanner.Text())
		}
	}

	for _, item := range r.options.FileInput {
		r.setItem(item)
	}

	for _, item := range r.options.Asn {
		r.setItem(item)
	}

	for _, item := range r.options.Ip {
		r.setItem(item)
	}

	for _, item := range r.options.Domain {
		r.setItem(item)
	}

	for _, item := range r.options.Org {
		r.setItem(item)
	}

	return nil
}
