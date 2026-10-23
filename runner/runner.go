package runner

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	syncutil "github.com/projectdiscovery/utils/sync"
)

type Runner struct {
	options  *Options
	hm       *hybrid.HybridMap
	client   *asnmap.Client
	outputMu sync.Mutex
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
			return fmt.Errorf("could not set proxy: %s", err)
		} else {
			gologger.Info().Msgf("Using %s proxy %s", proxyURL.Scheme, proxyURL.String())
		}
	}

	var outputWriters []io.Writer
	if r.options.OutputFile != "" {
		file, err := os.Create(r.options.OutputFile)
		if err != nil {
			return err
		}
		outputWriters = append(outputWriters, file)
	}

	outputWriters = append(outputWriters, os.Stdout)
	r.options.Output = io.MultiWriter(outputWriters...)

	if r.options.DisplayInCSV {
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

// process looks up every input with up to Threads concurrent workers
func (r *Runner) process() error {
	wg, err := syncutil.New(syncutil.WithSize(max(r.options.Threads, 1)))
	if err != nil {
		return err
	}
	var (
		errMu      sync.Mutex
		errProcess error
	)
	r.hm.Scan(func(key, _ []byte) error {
		errMu.Lock()
		err := errProcess
		errMu.Unlock()
		// stop scheduling new inputs once a worker hit a fatal error
		if err != nil {
			return err
		}
		item := string(key)
		wg.Add()
		go func() {
			defer wg.Done()
			if err := r.processItem(item); err != nil {
				errMu.Lock()
				if errProcess == nil {
					errProcess = err
				}
				errMu.Unlock()
			}
		}()
		return nil
	})
	wg.Wait()
	return errProcess
}

func (r *Runner) processItem(item string) error {
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
			if errors.Is(err, asnmap.ErrUnAuthorized) {
				return err
			}
			if err != nil {
				gologger.Error().Msgf("skipping %s (%s): %s", item, resolvedIp, err)
				continue
			}

			for _, l := range ls {
				if !sliceutil.Contains(responses, *l) {
					responses = append(responses, *l)
				}
			}
		}

		for _, response := range responses {
			if err := r.writeOutput([]*asnmap.Response{&response}); err != nil {
				return err
			}
		}

	default:
		ls, err := r.client.GetData(item)
		if errors.Is(err, asnmap.ErrUnAuthorized) {
			return err
		}
		if err != nil {
			gologger.Error().Msgf("skipping %s: %s", item, err)
			return nil
		}
		if len(ls) == 0 {
			gologger.Verbose().Msgf("No records found for %v", item)
			return nil
		}
		if err := r.writeOutput(ls); err != nil {
			return err
		}
	}

	return nil
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
