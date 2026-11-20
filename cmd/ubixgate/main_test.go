package main

import (
	"bytes"
	"strings"
	"testing"
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
