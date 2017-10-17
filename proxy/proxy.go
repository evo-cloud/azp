package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	oidcp "github.com/coreos/go-oidc"
	"github.com/coreos/go-oidc/oidc"
	"golang.org/x/oauth2"
)

// Config defines the parameters for proxy configuration
type Config struct {
	BackendURL  string
	ProxyURL    string
	TLSCertFile string
	TLSKeyFile  string
	OIDCIssuer  string
	ClientID    string
	Secret      string
	Scopes      []string
	UserAttr    string
	EmailAttr   string
	GroupsAttr  string
	RulesFile   string
}

// New creates proxy using config
func New(conf Config) (http.Handler, error) {
	backendURL, err := url.Parse(conf.BackendURL)
	if err != nil {
		return nil, err
	}
	var rbac *RBAC
	if conf.RulesFile != "" {
		rbac, err = LoadRulesFile(conf.RulesFile)
		if err != nil {
			return nil, err
		}
	}
	provider, err := oidcp.NewProvider(context.TODO(), conf.OIDCIssuer)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	proxy := &oidcProxy{
		config:   conf,
		provider: provider,
		verifier: provider.Verifier(&oidcp.Config{ClientID: conf.ClientID}),
		oauthConf: &oauth2.Config{
			ClientID:     conf.ClientID,
			ClientSecret: conf.Secret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  strings.TrimRight(conf.ProxyURL, "/") + "/.proxy/authcode",
			Scopes:       append([]string{oidcp.ScopeOpenID}, conf.Scopes...),
		},
		handler: mux,
		proxy:   httputil.NewSingleHostReverseProxy(backendURL),
		rbac:    rbac,
	}

	mux.HandleFunc("/.proxy/authcode", proxy.handleAuthCode)
	mux.HandleFunc("/", proxy.filter)

	return proxy, nil
}

type oidcProxy struct {
	config    Config
	provider  *oidcp.Provider
	verifier  *oidcp.IDTokenVerifier
	oauthConf *oauth2.Config
	rbac      *RBAC
	handler   http.Handler
	proxy     http.Handler
}

type userInfo struct {
	name   string
	email  string
	groups []string
}

const (
	cookieIDToken      = "azp-idtoken"
	cookieRefreshToken = "azp-refreshtoken"
	cookieExpiry       = "azp-expiry"
)

func (p *oidcProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.handler.ServeHTTP(w, r)
}

func (p *oidcProxy) handleAuthCode(w http.ResponseWriter, r *http.Request) {
	encodedURL := r.URL.Query().Get("state")
	originalURL, err := base64.URLEncoding.DecodeString(encodedURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid state: %s: %v", encodedURL, err), http.StatusBadRequest)
		return
	}
	log.Printf("AuthCode: original %s", string(originalURL))
	token, err := p.oauthConf.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, fmt.Sprintf("fail to exchange auth code: %v", err), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "bad token: id_token unavailable", http.StatusBadRequest)
		return
	}
	if _, err = p.verifier.Verify(r.Context(), rawIDToken); err != nil {
		http.Error(w, fmt.Sprintf("bad token: verification failed: %v", err), http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieIDToken,
		Value:    rawIDToken,
		Expires:  token.Expiry,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     cookieExpiry,
		Value:    strconv.FormatInt(token.Expiry.UTC().Unix(), 10),
		Expires:  token.Expiry,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
	})
	if refreshToken, ok := token.Extra("refresh_token").(string); ok {
		http.SetCookie(w, &http.Cookie{
			Name:     cookieRefreshToken,
			Value:    refreshToken,
			Expires:  token.Expiry,
			Path:     "/",
			Secure:   true,
			HttpOnly: true,
		})
	}
	log.Printf("AuthCode: redirect to original %s", string(originalURL))
	http.Redirect(w, r, string(originalURL), http.StatusFound)
}

func (p *oidcProxy) filter(w http.ResponseWriter, r *http.Request) {
	user := p.authentication(w, r)
	if user == nil {
		return
	}
	if p.rbac != nil && !p.rbac.authorize(r, user) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p.proxy.ServeHTTP(w, r)
}

func (p *oidcProxy) authentication(w http.ResponseWriter, r *http.Request) *userInfo {
	authHeader := true
	rawToken, err := oidc.ExtractBearerToken(r)
	if err != nil {
		authHeader = false
		cookie, err := r.Cookie(cookieIDToken)
		if err != nil {
			p.unauthenticated(w, r, authHeader)
			return nil
		}
		rawToken = cookie.Value
	}

	idToken, err := p.verifier.Verify(r.Context(), rawToken)
	if err != nil {
		p.unauthenticated(w, r, authHeader)
		return nil
	}

	var attrs map[string]interface{}
	if err = idToken.Claims(&attrs); err != nil {
		p.unauthenticated(w, r, authHeader)
		return nil
	}

	user := &userInfo{}
	if v, ok := attrs[p.config.UserAttr].(string); ok {
		user.name = v
	}
	if v, ok := attrs[p.config.EmailAttr].(string); ok {
		user.email = v
	}
	if v, ok := attrs[p.config.GroupsAttr].([]interface{}); ok {
		for _, item := range v {
			if s, ok := item.(string); ok {
				user.groups = append(user.groups, s)
			}
		}
	}

	return user
}

func (p *oidcProxy) unauthenticated(w http.ResponseWriter, r *http.Request, authHeader bool) {
	if authHeader || r.Method != http.MethodGet {
		log.Println("Unauthenticated")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("unauthorized"))
	} else {
		loginURL := p.oauthConf.AuthCodeURL(base64.URLEncoding.EncodeToString([]byte(r.URL.String())))
		log.Printf("Unauthenticated, login to %s", loginURL)
		http.Redirect(w, r, loginURL, http.StatusFound)
	}
}
