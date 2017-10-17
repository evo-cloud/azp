package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Run simply runs the server
func Run(conf Config) error {
	proxyURL, err := url.Parse(conf.ProxyURL)
	if err != nil {
		return err
	}

	port := 80
	if portStr := proxyURL.Port(); portStr != "" {
		customPort, e := strconv.Atoi(portStr)
		if e != nil {
			return e
		}
		port = customPort
	} else if strings.ToLower(proxyURL.Scheme) == "https" {
		port = 443
	}

	handler, err := New(conf)
	if err != nil {
		return err
	}

	return http.ListenAndServeTLS(fmt.Sprintf(":%d", port),
		conf.TLSCertFile, conf.TLSKeyFile, handler)
}
