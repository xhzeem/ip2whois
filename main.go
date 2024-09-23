package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

// Fetch the IP2Whois API with a given key and domain
func fetchIP2Whois(apiKey, domain string) (string, error) {
	url := fmt.Sprintf("https://api.ip2whois.com/v2?key=%s&domain=%s", apiKey, domain)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Check for non-200 status code
	if resp.StatusCode != 200 {
		return "", errors.New(fmt.Sprintf("Error: Received status code %d", resp.StatusCode))
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Parse the response to check if it contains an error
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	if _, ok := result["error"]; ok {
		return "", errors.New("API key failed: error in response")
	}

	return string(body), nil
}

// Recursively filter out fields that contain the word "REDACTED" or are empty
func removeRedactedAndEmptyFields(data map[string]interface{}) map[string]interface{} {
	cleaned := make(map[string]interface{})

	for key, value := range data {
		switch v := value.(type) {
		case string:
			// If the value is a string, check if it contains "REDACTED" or if it's empty
			if v != "" && !strings.Contains(v, "REDACTED") {
				cleaned[key] = v
			}
		case map[string]interface{}:
			// Recursively clean nested objects
			cleanedNested := removeRedactedAndEmptyFields(v)
			if len(cleanedNested) > 0 {
				cleaned[key] = cleanedNested
			}
		case []interface{}:
			// Handle arrays, remove if they are empty
			if len(v) > 0 {
				cleaned[key] = v
			}
		default:
			// Keep other data types (numbers, booleans, etc.) but remove `null` values
			if v != nil {
				cleaned[key] = v
			}
		}
	}

	return cleaned
}

func main() {
	// Command line flags
	apiKeys := flag.String("k", "", "Comma-separated list of API keys for ip2whois")
	domain := flag.String("d", "", "Domain to fetch the whois information for")
	hideRedacted := flag.Bool("clean", false, "Hide fields containing the word 'REDACTED' and empty fields")
	flag.Parse()

	// Ensure a domain is provided
	if *domain == "" {
		fmt.Println("Error: Domain (-d) flag is required.")
		os.Exit(1)
	}

	// Ensure API keys are provided
	if *apiKeys == "" {
		fmt.Println("Error: API keys (-k) flag is required.")
		os.Exit(1)
	}

	// Split the keys by comma into a slice
	keys := strings.Split(*apiKeys, ",")

	// Try each API key until one works
	var success bool
	for _, key := range keys {
		response, err := fetchIP2Whois(strings.TrimSpace(key), *domain)
		if err == nil {

			var jsonData map[string]interface{}
			if err := json.Unmarshal([]byte(response), &jsonData); err != nil {
				fmt.Printf("Error parsing JSON: %v\n", err)
				os.Exit(1)
			}

			if *hideRedacted {
				// Remove redacted and empty fields if the flag is set
				jsonData = removeRedactedAndEmptyFields(jsonData)
			}

			// Print the cleaned JSON
			cleanedOutput, err := json.MarshalIndent(jsonData, "", "  ")
			if err != nil {
				fmt.Printf("Error formatting JSON: %v\n", err)
				os.Exit(1)
			}

			fmt.Println(string(cleanedOutput))
			success = true
			break
		}
	}

	if !success {
		fmt.Println("All API keys failed.")
		os.Exit(1)
	}
}
