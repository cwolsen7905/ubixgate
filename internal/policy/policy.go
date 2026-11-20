// Package policy decides whether a principal may see or call a tool.
//
// Rules are evaluated deny first, then allow, each in file order; the first rule that
// matches decides. If nothing matches, the call is denied by the built-in rule
// "default-deny". A rule matches when every field it sets matches.
//
// Globs use path.Match: "*" matches any run of characters except "/", "?" one
// character, and "[...]" a character class. Globs match the raw string. An upstream that
// normalises its input differently (for example "myorg/.." to "") can defeat an argument
// constraint, so constraints are only as good as the upstream's own parsing.
package policy

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
)

// Names of the built-in rules. A configured rule may not use them.
const (
	DefaultDeny = "default-deny"
	UnknownTool = "unknown-tool"
)

// Effect is what a rule does when it matches.
type Effect string

const (
	Allow Effect = "allow"
	Deny  Effect = "deny"
)

// Principal is who is acting: an authenticated user, their groups, and the client
// they are using (from a signed claim, so attribution rather than a boundary).
type Principal struct {
	User   string
	Groups []string
	Client string
}

// ClientRequestKinds are what an upstream may ask of the caller's client during a call.
var ClientRequestKinds = []string{"sampling", "elicitation", "roots"}

// Request is one tool call to decide on, or, with ClientRequest set, one request an
// upstream made of the caller's client while serving that call.
type Request struct {
	Principal     Principal
	Server        string
	Tool          string
	Args          map[string]any
	ClientRequest string // empty for the call itself
}

// Decision is the outcome of a Request. Rule names the rule that decided, which a
// denial and the audit record both show. AuditArgs lists the argument names whose values
// may be logged.
type Decision struct {
	Effect    Effect
	Rule      string
	AuditArgs []string
}

// Allowed reports whether the decision permits the call.
func (d Decision) Allowed() bool { return d.Effect == Allow }

// Decider is the policy engine interface. The YAML rule list is the only implementation;
// another engine (OPA, CEL) would be a second one.
type Decider interface {
	Decide(ctx context.Context, req Request) (Decision, error)
	// Visible reports whether a tool belongs in the principal's catalog.
	Visible(p Principal, server, tool string) bool
}

// When narrows a rule to some principals. Each set field must match; within a field,
// any listed value matches.
type When struct {
	Users   []string `yaml:"users"`
	Groups  []string `yaml:"groups"`
	Clients []string `yaml:"clients"`
}

// Rule is one entry of the policy, as written in the config file.
type Rule struct {
	Name      string            `yaml:"name"`
	Effect    Effect            `yaml:"effect"`
	When      When              `yaml:"when"`
	Server    string            `yaml:"server"`
	Tools     []string          `yaml:"tools"`
	Args      map[string]string `yaml:"args"`
	AuditArgs []string          `yaml:"audit_args"`
	// ClientRequests makes the rule apply to these kinds of upstream requests to the
	// caller's client, and not to tool calls. Without it, a rule applies only to calls.
	ClientRequests []string `yaml:"client_requests"`
}

// Rules is a validated rule list. It implements Decider.
type Rules struct {
	deny, allow []Rule
}

var _ Decider = (*Rules)(nil)

// New validates rules and returns them ready to evaluate. servers is the set of
// configured upstream names; a rule whose server glob matches none of them is an error,
// since it could never apply.
func New(rules []Rule, servers []string) (*Rules, error) {
	var errs []error
	seen := map[string]bool{}
	r := &Rules{}
	for i, rule := range rules {
		bad := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("policy rule %d (%q): %s", i+1, rule.Name, fmt.Sprintf(format, a...)))
		}
		switch {
		case rule.Name == "":
			bad("name is required")
		case rule.Name == DefaultDeny || rule.Name == UnknownTool:
			bad("name is reserved for a built-in rule")
		case seen[rule.Name]:
			bad("name is used by an earlier rule")
		}
		seen[rule.Name] = true
		if rule.Effect != Allow && rule.Effect != Deny {
			bad("effect must be allow or deny, not %q", rule.Effect)
		}
		if rule.Server == "" {
			bad(`server is required (use "*" for any)`)
		} else if !validGlob(rule.Server) {
			bad("server %q is not a valid glob", rule.Server)
		} else if !slices.ContainsFunc(servers, func(s string) bool { return match(rule.Server, s) }) {
			bad("server %q matches no configured upstream", rule.Server)
		}
		if len(rule.Tools) == 0 {
			bad(`tools is required (use ["*"] for any)`)
		}
		for _, t := range rule.Tools {
			if !validGlob(t) {
				bad("tool %q is not a valid glob", t)
			}
		}
		for k, v := range rule.Args {
			if !validGlob(v) {
				bad("args.%s %q is not a valid glob", k, v)
			}
		}
		for _, k := range rule.ClientRequests {
			if !slices.Contains(ClientRequestKinds, k) {
				bad("client_requests: %q is not one of %v", k, ClientRequestKinds)
			}
		}
		if rule.Effect == Deny {
			r.deny = append(r.deny, rule)
		} else {
			r.allow = append(r.allow, rule)
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return r, nil
}

// Decide evaluates req: deny rules first, then allow rules, first match wins.
func (r *Rules) Decide(_ context.Context, req Request) (Decision, error) {
	for _, rule := range r.deny {
		if rule.decides(req) {
			return Decision{Effect: Deny, Rule: rule.Name}, nil
		}
	}
	for _, rule := range r.allow {
		if rule.decides(req) {
			return Decision{Effect: Allow, Rule: rule.Name, AuditArgs: rule.AuditArgs}, nil
		}
	}
	return Decision{Effect: Deny, Rule: DefaultDeny}, nil
}

// decides reports whether the rule matches req, kind of request included.
func (rule Rule) decides(req Request) bool {
	kindOK := len(rule.ClientRequests) == 0 && req.ClientRequest == "" ||
		req.ClientRequest != "" && slices.Contains(rule.ClientRequests, req.ClientRequest)
	return kindOK && rule.matches(req.Principal, req.Server, req.Tool) && rule.argsMatch(req.Args)
}

// Visible reports whether a tool is listed for p: some allow rule matches it with its
// argument constraints ignored, and no deny rule without argument constraints matches.
// A listed tool can still be denied for its arguments, because the permitted values
// cannot be expressed in a listing.
func (r *Rules) Visible(p Principal, server, tool string) bool {
	for _, rule := range r.deny {
		if len(rule.Args) == 0 && len(rule.ClientRequests) == 0 && rule.matches(p, server, tool) {
			return false
		}
	}
	for _, rule := range r.allow {
		if len(rule.ClientRequests) == 0 && rule.matches(p, server, tool) {
			return true
		}
	}
	return false
}

// matches checks everything but the arguments.
func (rule Rule) matches(p Principal, server, tool string) bool {
	w := rule.When
	if len(w.Users) > 0 && !slices.Contains(w.Users, p.User) {
		return false
	}
	if len(w.Groups) > 0 && !slices.ContainsFunc(w.Groups, func(g string) bool { return slices.Contains(p.Groups, g) }) {
		return false
	}
	if len(w.Clients) > 0 && !slices.Contains(w.Clients, p.Client) {
		return false
	}
	if !match(rule.Server, server) {
		return false
	}
	return slices.ContainsFunc(rule.Tools, func(t string) bool { return match(t, tool) })
}

// argsMatch requires each constrained argument to be present, a string, and match.
func (rule Rule) argsMatch(args map[string]any) bool {
	for k, glob := range rule.Args {
		s, ok := args[k].(string)
		if !ok || !match(glob, s) {
			return false
		}
	}
	return true
}

func match(glob, s string) bool {
	ok, err := path.Match(glob, s)
	return err == nil && ok
}

func validGlob(glob string) bool {
	_, err := path.Match(glob, "")
	return err == nil
}
