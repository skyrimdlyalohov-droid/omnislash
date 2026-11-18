package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/skyrimdlyalohov-droid/omnislash"
)

func cmdFetch(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	common := addCommonFlags(fs)
	urlStr := fs.String("url", "https://api.ipify.org", "URL для проверки ротации")
	n := fs.Int("n", 5, "сколько запросов сделать")
	concurrency := fs.Int("concurrency", 5, "параллельных запросов")
	insecure := fs.Bool("insecure", false, "не проверять TLS-сертификат")
	showBody := fs.Bool("show-body", true, "печатать тело ответа (до 4 КиБ)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *n < 1 {
		return fmt.Errorf("-n должно быть >= 1")
	}
	if *concurrency < 1 {
		*concurrency = 1
	}

	cfg, proxies, logger, err := common.load()
	if err != nil {
		return err
	}
	if *insecure {
		cfg.HTTP.TLSSkipVerify = true
	}
	pool, err := omnislash.NewPool(cfg, proxies, logger)
	if err != nil {
		return err
	}
	dialer := omnislash.NewDialer(pool, logger)
	transport := omnislash.NewRotatingTransport(pool, dialer, cfg.HTTP, logger)
	defer transport.Close()
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.HTTP.Timeout.Std(),
	}

	ctx, stop := signalContext()
	defer stop()

	type result struct {
		idx      int
		status   int
		duration time.Duration
		body     string
		err      error
	}
	jobs := make(chan int)
	results := make(chan result, *n)
	var wg sync.WaitGroup
	var failed atomic.Int64

	worker := func() {
		defer wg.Done()
		for i := range jobs {
			res := result{idx: i}
			start := time.Now()
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, *urlStr, nil)
			if reqErr != nil {
				res.err = reqErr
			} else {
				req.Header.Set("User-Agent", "omnislash/"+version)
				resp, doErr := client.Do(req)
				if doErr != nil {
					res.err = doErr
				} else {
					res.status = resp.StatusCode
					if *showBody {
						b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
						res.body = strings.TrimSpace(string(b))
					}
					_ = resp.Body.Close()
				}
			}
			res.duration = time.Since(start)
			if res.err != nil {
				failed.Add(1)
			}
			results <- res
		}
	}

	workers := *concurrency
	if workers > *n {
		workers = *n
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}
	go func() {
		for i := 1; i <= *n; i++ {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.err != nil {
			fmt.Printf("#%d\tERR\t%s\t%v\n", res.idx, res.duration.Round(time.Millisecond), res.err)
			continue
		}
		body := res.body
		if len(body) > 120 {
			body = body[:120] + "…"
		}
		fmt.Printf("#%d\t%d\t%s\t%s\n", res.idx, res.status, res.duration.Round(time.Millisecond), body)
	}

	if int(failed.Load()) == *n {
		return fmt.Errorf("все запросы завершились ошибкой")
	}
	return nil
}
