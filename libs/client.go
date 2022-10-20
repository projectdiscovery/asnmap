package asnmap

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	url "net/url"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
	"golang.org/x/net/proxy"

	"reflect"
	"sync"
)

const serverURL = "https://api.asnmap.sh/"

type Syncer struct {
	dedup sync.Map
}

type Client struct {
	url  url.URL
	http http.Client
	sync *Syncer
}

// generatefullURL creates the complete URL with path, scheme, and host
func generateFullURL(host string) string {
	rawURL, _ := url.Parse(host)

	if rawURL.Scheme != "http" && rawURL.Scheme != "https" {
		gologger.Fatal().Msgf("Host should start with http or https.")
	}

	u := url.URL{Scheme: rawURL.Scheme, Host: rawURL.Host, Path: "api/v1/asnmap"}
	return u.String()
}

// If SERVER_URL env provider use that else use serverURL constant
func getURL() string {
	url := os.Getenv("SERVER_URL")
	if url == "" {
		url = serverURL
	}
	return generateFullURL(url)
}

func NewClient() *Client {
	URL := getURL()
	u, _ := url.Parse(URL)

	// ignore expired SSL certificates
	transCfg := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := Client{
		url: url.URL{
			Scheme: u.Scheme,
			Host:   u.Host,
			Path:   u.Path,
		},
		http: http.Client{Transport: transCfg},
		sync: &Syncer{},
	}
	return &client
}

// SetProxy adds a proxy to the client
func (c *Client) SetProxy(proxyList []string) error {
	for _, p := range proxyList {
		if proxyurl, err := c.setProxy(p); err == nil {
			gologger.Info().Msgf("Using %s proxy %s", proxyurl.Scheme, proxyurl.String())
			return nil
		} else {
			if fileutil.FileExists(p) {
				if proxyurl, err := c.setProxyFromFile(p); err == nil {
					gologger.Info().Msgf("Using %s proxy %s", proxyurl.Scheme, proxyurl.String())
					return nil
				}
			}
		}
	}
	return errors.New("no valid proxy found")
}

// setProxyFromFile reads the file contents and tries to set the proxy
func (c *Client) setProxyFromFile(fileName string) (*url.URL, error) {
	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		proxy := strings.TrimSpace(scanner.Text())
		if proxy == "" {
			continue
		}
		if proxyurl, err := c.setProxy(proxy); err == nil {
			gologger.Info().Msgf("Using proxy %s", proxy)
			return proxyurl, nil
		}
	}
	return nil, fmt.Errorf("no valid proxy found")
}

// setProxy sets a proxy to the client
func (c *Client) setProxy(proxyString string) (*url.URL, error) {
	// parse the proxy url string
	proxyurl, err := url.Parse(proxyString)
	if err != nil {
		return nil, err
	}

	// try to connect to the proxy
	_, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%s", proxyurl.Hostname(), proxyurl.Port()), time.Second*5)
	if err != nil {
		return nil, err
	}

	if proxyurl.Scheme == "http" || proxyurl.Scheme == "https" {
		c.http.Transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyurl),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		return proxyurl, nil
	}
	if proxyurl.Scheme == "socks5" {
		dialer, err := proxy.SOCKS5("tcp", proxyurl.Host, nil, proxy.Direct)
		if err != nil {
			return nil, err
		}
		c.http.Transport = &http.Transport{
			Dial: dialer.Dial,
		}
		return proxyurl, nil
	}
	return nil, fmt.Errorf("invalid proxy scheme: %s", proxyurl.Scheme)
}

func generateRawQuery(query, value string) string {
	return query + "=" + value
}

func insertInputInResponse(input string, resp []Response) []Response {
	expectedResponse := []Response{}

	for _, res := range resp {
		res.Input = input
		expectedResponse = append(expectedResponse, res)
	}

	return expectedResponse
}

func (c Client) makeRequest() ([]byte, error) {
	req, _ := http.NewRequest("GET", c.url.String(), nil)
	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	resBody, _ := ioutil.ReadAll(res.Body)
	return resBody, nil
}

func (c Client) GetData(value interface{}, originalValue ...interface{}) []Response {

	var input interface{}
	if len(originalValue) == 1 {
		input = originalValue[0]
	} else {
		input = value
	}

	outC := []Response{}
	switch v := value.(type) {
	case ASN:
		c.url.RawQuery = generateRawQuery("asn", string(v))
	case IP:
		c.url.RawQuery = generateRawQuery("ip", string(v))
	case Org:
		c.url.RawQuery = generateRawQuery("org", string(v))
	}
	resp, err := c.makeRequest()

	if err != nil {
		gologger.Fatal().Msgf("%s\n", err)
	}

	resultList := []Response{}
	err = json.Unmarshal(resp, &resultList)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	out, err := json.Marshal(resultList)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}

	hash := string(out)
	if _, ok := c.sync.dedup.Load(hash); !ok {
		c.sync.dedup.Store(hash, resultList)
		outC = insertInputInResponse(reflect.ValueOf(input).String(), resultList)
	}

	return outC
}
