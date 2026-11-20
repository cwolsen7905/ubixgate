package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ubixsys/ubixgate/internal/audit"
)

func TestRun(t *testing.T) {
	cases := []struct {
		args []string
		code int
		out  string
	}{
		{[]string{"version"}, 0, "ubixgate dev\n"},
		{nil, 2, ""},
		{[]string{"nope"}, 2, ""},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		if got := run(c.args, &out, &errb); got != c.code {
			t.Errorf("run(%q) = %d, want %d", c.args, got, c.code)
		}
		if c.out != "" && out.String() != c.out {
			t.Errorf("run(%q) printed %q, want %q", c.args, out.String(), c.out)
		}
		if c.code != 0 && !strings.Contains(errb.String(), "usage:") {
			t.Errorf("run(%q) should print usage on stderr", c.args)
		}
	}
}

func TestPolicyExplain(t *testing.T) {
	const cfg = "../../internal/config/testdata/full.yaml"
	cases := []struct {
		args []string
		code int
		want []string
	}{
		{[]string{"-user", "alice", "-groups", "developers", "-client", "claude-code", "-tool", "tickets__ticket_create", "-arg", "project=myorg/web"},
			0, []string{"decision: allow", "rule:     devs-tickets-own-project", "listed:   true", "logged:   project"}},
		{[]string{"-user", "alice", "-groups", "developers", "-client", "claude-code", "-tool", "tickets__ticket_create", "-arg", "project=other/x"},
			1, []string{"decision: deny", "rule:     default-deny", "listed:   true"}},
		{[]string{"--user", "bob", "--groups", "contractors", "--tool", "tickets__ticket_delete"},
			1, []string{"rule:     contractors-no-writes", "listed:   false"}},
		{[]string{"-user", "eve", "-tool", "jira__x"},
			1, []string{"rule:     unknown-tool", "shown:    denied by rule default-deny"}},
		{[]string{"-user", "alice", "-groups", "developers", "-tool", "tickets__ticket_create", "-client-request", "sampling"},
			1, []string{"rule:     default-deny"}},
		// A client request comes only from a tool the gateway is running, so an unknown
		// tool is a usage error, never a decision the gateway could not make.
		{[]string{"-user", "alice", "-tool", "jira__x", "-client-request", "sampling"}, 2, nil},
		{[]string{"-user", "alice", "-tool", "tickets", "-client-request", "sampling"}, 2, nil},
		{[]string{"-user", "alice"}, 2, nil},
		{[]string{"-tool", "tickets__x", "-arg", "noequals"}, 2, nil},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		args := append([]string{"policy", "explain", "-config", cfg}, c.args...)
		if got := run(args, &out, &errb); got != c.code {
			t.Errorf("%q: exit %d, want %d (%s)", c.args, got, c.code, errb.String())
		}
		for _, w := range c.want {
			if !strings.Contains(out.String(), w) {
				t.Errorf("%q: output lacks %q:\n%s", c.args, w, out.String())
			}
		}
	}
}

func TestAuditVerify(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	log := filepath.Join(dir, "audit.jsonl")
	_ = os.WriteFile(key, []byte("0123456789abcdef0123456789abcdef\n"), 0o600)
	k, _ := os.ReadFile(key)
	s, err := audit.OpenFile(log, []byte(strings.TrimSpace(string(k))))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"alice", "bob", "carol"} {
		_ = s.Write(audit.Record{User: u, Tool: "t__x"})
	}
	_ = s.Close()
	verify := func() (int, string) {
		var out, errb bytes.Buffer
		code := run([]string{"audit", "verify", "-key", key, log}, &out, &errb)
		return code, out.String() + errb.String()
	}
	if code, out := verify(); code != 0 || !strings.Contains(out, "ok, 3 records") {
		t.Fatalf("intact: %d %s", code, out)
	}
	b, _ := os.ReadFile(log)
	_ = os.WriteFile(log, bytes.Replace(b, []byte(`"user":"bob"`), []byte(`"user":"eve"`), 1), 0o600)
	if code, out := verify(); code != 1 || !strings.Contains(out, "line 2: chain does not follow") || !strings.Contains(out, "Line 1 verifies.") {
		t.Errorf("tampered: %d %s", code, out)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"audit", "verify", "-key", filepath.Join(dir, "missing"), log}, &out, &errb); code != 1 {
		t.Errorf("missing key: exit %d", code)
	}
}
