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
