package main

import (
	"flag"
	"log"
	"strings"

	"github.com/evo-cloud/azp/proxy"
)

func main() {
	var conf proxy.Config
	var scopes string
	flag.StringVar(&conf.BackendURL, "b", "http://localhost:8080", "base URL for backend")
	flag.StringVar(&conf.ProxyURL, "l", "https://localhost:8443", "externally accessible URL for this proxy server")
	flag.StringVar(&conf.TLSCertFile, "cert", "cert.pem", "certificate file")
	flag.StringVar(&conf.TLSKeyFile, "key", "key.pem", "private key file")
	flag.StringVar(&conf.OIDCIssuer, "oidc-issuer", "https://accounts.google.com", "OIDC issuer URL")
	flag.StringVar(&conf.ClientID, "c", "", "OIDC client ID")
	flag.StringVar(&conf.Secret, "s", "", "OIDC client secret")
	flag.StringVar(&scopes, "scopes", "profile,email", "additional OIDC scopes, comma-separated")
	flag.StringVar(&conf.UserAttr, "user-attr", "name", "attribute name to map username")
	flag.StringVar(&conf.EmailAttr, "email-attr", "email", "attribute name to map email")
	flag.StringVar(&conf.GroupsAttr, "groups-attr", "groups", "attribute name to map groups")
	flag.StringVar(&conf.RulesFile, "rbac-rules", "", "rules file for RBAC")

	flag.Parse()

	items := strings.Split(scopes, ",")
	for _, item := range items {
		if item != "openid" {
			conf.Scopes = append(conf.Scopes, item)
		}
	}

	if err := proxy.Run(conf); err != nil {
		log.Fatalln(err)
	}
}
