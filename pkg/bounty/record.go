package bounty

import (
	log "github.com/sirupsen/logrus"
)

// RecordCredential handles storing and reporting logged credentials
func RecordCredential(proto string, source string, params map[string]string) {

	lf := log.Fields{
		"proto": proto,
		"src":   source,
	}
	for k, v := range params {
		if _, exists := lf[k]; exists {
			continue
		}
		lf[k] = v
	}
	log.WithFields(lf).Info()
}
