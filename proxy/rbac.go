package proxy

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

// Matcher matches a request
type Matcher func(*http.Request) bool

// Rule defines a single rule matching a single request
type Rule struct {
	ID      string
	Matcher Matcher
}

// Binding defines user names/emails/groups bounded to an action
type Binding struct {
	Rule     string
	Allows   map[string]bool
	AllowAll bool
}

func (b *Binding) isAllowed(user *userInfo) bool {
	var allow, exist bool
	if user.email != "" {
		allow, exist = b.Allows[strings.ToLower(user.email)]
	}
	if !exist && user.name != "" {
		allow, exist = b.Allows[strings.ToLower(user.name)]
	}
	if !exist {
		for _, g := range user.groups {
			if g == "" {
				continue
			}
			if allow, exist = b.Allows[strings.ToLower(g)]; exist {
				break
			}
		}
	}
	if exist {
		return allow
	}
	return b.AllowAll
}

// RBAC defines rules and bindings
type RBAC struct {
	Rules    []Rule
	Bindings map[string]*Binding
}

func (f *RBAC) authorize(r *http.Request, user *userInfo) bool {
	for _, rule := range f.Rules {
		if rule.Matcher(r) {
			b := f.Bindings[rule.ID]
			if b != nil && b.isAllowed(user) {
				return true
			}
			log.Printf("RBAC Deny [rule=%s]: %s; user: %s<%s>\n",
				rule.ID, r.URL.Path, user.name, user.email)
			return false
		}
	}
	log.Printf("RBAC Deny [default]: %s; user: %s<%s>\n",
		r.URL.Path, user.name, user.email)
	return false
}

// RulesFile defines file format of rules and bindings
type RulesFile struct {
	Rules    []RuleDef           `json:"rules"`
	Bindings map[string][]string `json:"bindings"`
}

// RuleDef defines the rule definition in rules file
type RuleDef struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

// LoadRulesFile load rules from file
func LoadRulesFile(fn string) (*RBAC, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var def RulesFile
	if err = json.NewDecoder(f).Decode(&def); err != nil {
		return nil, err
	}
	return def.BuildRBAC()
}

// BuildRBAC builds RBAC from rules file
func (d *RulesFile) BuildRBAC() (*RBAC, error) {
	rbac := &RBAC{Bindings: make(map[string]*Binding)}
	for _, def := range d.Rules {
		rbac.Rules = append(rbac.Rules, Rule{
			ID:      def.ID,
			Matcher: matcher(def),
		})
	}
	for rule, names := range d.Bindings {
		b := &Binding{Rule: rule, Allows: make(map[string]bool)}
		for _, name := range names {
			name = strings.ToLower(name)
			allow := true
			if strings.HasPrefix(name, "-") {
				name = name[1:]
				allow = false
			} else if strings.HasPrefix(name, "+") {
				name = name[1:]
			}
			if name == "*" {
				b.AllowAll = allow
			} else {
				b.Allows[name] = allow
			}
		}
		rbac.Bindings[rule] = b
	}
	return rbac, nil
}

func matcher(def RuleDef) Matcher {
	methods := make(map[string]bool)
	for _, m := range strings.Split(strings.ToUpper(def.Method), "|") {
		if m == "*" {
			methods = nil
			break
		} else if m != "" {
			methods[m] = true
		}
	}
	if len(methods) == 0 {
		methods = nil
	}
	var pathMatcher func(string) bool
	if strings.HasSuffix(def.Path, "/") {
		prefix := strings.TrimRight(def.Path, "/")
		if prefix == "" {
			pathMatcher = func(string) bool { return true }
		} else {
			pathMatcher = func(a string) bool {
				if strings.HasPrefix(a, prefix) {
					return len(a) == len(prefix) || a[len(prefix)] == '/'
				}
				return false
			}
		}
	} else {
		pathMatcher = func(a string) bool {
			return strings.HasPrefix(a, def.Path)
		}
	}
	return func(r *http.Request) bool {
		if methods != nil && !methods[r.Method] {
			return false
		}
		return pathMatcher(r.URL.Path)
	}
}
