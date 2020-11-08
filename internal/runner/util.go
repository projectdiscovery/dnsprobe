package runner

import (
	"bufio"
	"net/url"
	"os"
	"strings"
)

func fileExists(fileName string) bool {
	info, err := os.Stat(fileName)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

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

func prepareResolver(resolver string) string {
	resolver = strings.TrimSpace(resolver)
	if !strings.Contains(resolver, ":") {
		resolver += ":53"
	}
	return resolver
}
