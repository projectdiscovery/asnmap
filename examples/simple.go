package main

import (
	"encoding/json"
	"log"

	asnmap "github.com/projectdiscovery/asnmap/libs"
)

func main() {
	client, err := asnmap.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	items := []string{
		// Query based on ASN
		"14421",
		// Query based on IP
		"210.10.122.10",
		// Query based on Organization
		"pplinknet",
	}
	for _, item := range items {
		handleInput(client, item)
	}

	// Query based on domain
	domain := "hackerone.com"
	resolvedIps, err := asnmap.ResolveDomain(domain)
	if err != nil {
		log.Fatal(err)
	}
	for _, ip := range resolvedIps {
		handleInput(client, ip)
	}
}

func handleInput(client *asnmap.Client, item string) {
	responses, err := client.GetData(item)
	if err != nil {
		log.Fatal(err)
	}
	results, err := asnmap.MapToResults(responses)
	if err != nil {
		log.Fatal(err)
	}

	output, err := json.Marshal(results)
	if err != nil {
		log.Fatal(err)
	}

	if len(output) > 0 {
		log.Printf("%s: %s", item, string(output))
	}
}
