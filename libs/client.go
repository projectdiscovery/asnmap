package asnmap

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	url "net/url"
	"os"

	"github.com/projectdiscovery/gologger"

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
