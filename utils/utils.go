package utils

import (
	"regexp"
	"strings"
)

var MAIL_REGEX = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

//RemoveBlankStrings returns slice without blank strings
func RemoveBlankStrings(input []string) []string {
	u := make([]string, 0, len(input))
	for _, val := range input {
		if strings.TrimSpace(val) != "" {
			u = append(u, val)
		}
	}

	return u
}

// TrimSuffix remove trailing plus sign(s).
func TrimSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		s = s[:len(s)-len(suffix)]
	}
	return s
}
