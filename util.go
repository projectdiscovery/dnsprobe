package main

import (
	"bufio"
	"net/url"
	"os"
)

func linesInFile(fileName string) ([]string, error) {
	result := []string{}
	f, err := os.Open(fileName)
	if err != nil {
		return result, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	return result, nil
}

// isURL tests a string to determine if it is a well-structured url or not.
func isURL(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}

	return true
}

func extractDomain(URL string) string {
	u, err := url.Parse(URL)
	if err != nil {
		return ""
	}

	return u.Hostname()
}
