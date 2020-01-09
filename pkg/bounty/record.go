package bounty

import (
	log "github.com/sirupsen/logrus"
	"strings"
)

// RecordCredential handles storing and reporting logged credentials
func RecordCredential(proto string, source string, params map[string]string) {

	lf := log.Fields{
		"_proto": proto,
		"_src":   source,
	}
	for k, v := range params {
		if strings.HasPrefix(k, "_") {
			continue
		}
		lf[k] = v

	}
	log.WithFields(lf).Info()
}
