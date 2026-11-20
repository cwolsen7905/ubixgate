package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ubixsys/ubixgate/internal/audit"
	"github.com/ubixsys/ubixgate/internal/policy"
)

// Client requests are what an upstream asks of the caller's client during a call:
// sampling, elicitation, roots. Under MCP 2026-07-28 the upstream returns them in an
// "input required" result; the client answers and retries the call with the answers
// and the upstream's opaque request state. The gateway decides on each request,
// audits it, and seals the upstream's state to the caller, so only the same user can
// continue the same call.

// RuleRequestState is the rule a retry with a missing, forged, expired or another
// user's request state shows.
const RuleRequestState = "invalid-request-state"

const stateTTL = 10 * time.Minute

type sealedState struct {
	User     string   `json:"u"`
	Tool     string   `json:"t"`
	IDs      []string `json:"i"`
	Upstream string   `json:"s"`
	Expires  int64    `json:"e"`
}

func (g *Gateway) seal(st sealedState) string {
	b, _ := json.Marshal(st)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(g.mac(b))
}

// open checks a retry's state and answers, and returns the upstream's own state.
func (g *Gateway) open(token, user, tool string, answers mcp.InputResponseMap) (string, bool) {
	body, sig, _ := strings.Cut(token, ".")
	b, err1 := base64.RawURLEncoding.DecodeString(body)
	m, err2 := base64.RawURLEncoding.DecodeString(sig)
	var st sealedState
	if err1 != nil || err2 != nil || !hmac.Equal(m, g.mac(b)) || json.Unmarshal(b, &st) != nil ||
		st.User != user || st.Tool != tool || time.Now().Unix() > st.Expires {
		return "", false
	}
	for id := range answers {
		if !slices.Contains(st.IDs, id) {
			return "", false
		}
	}
	return st.Upstream, true
}

func (g *Gateway) mac(b []byte) []byte {
	h := hmac.New(sha256.New, g.opts.StateKey)
	h.Write(b)
	return h.Sum(nil)
}

// kindOf names a request for policy and audit. Sampling and roots are deprecated in
// 2026-07-28 (SEP-2577) but still in use during the deprecation window, so they are
// still decided on like elicitation.
func kindOf(ir mcp.InputRequest) string {
	switch ir.(type) {
	case *mcp.CreateMessageParams, *mcp.CreateMessageWithToolsParams: //nolint:staticcheck // see above
		return "sampling"
	case *mcp.ElicitParams:
		return "elicitation"
	case *mcp.ListRootsParams: //nolint:staticcheck // see above
		return "roots"
	}
	return "unknown"
}

// needsInput handles an upstream result that asks for client input: one audit record
// per request, then either the requests go back to the caller with sealed state, or the
// call fails because policy denied one or the client cannot receive them. It returns
// the result and the deny rule, if any.
func (g *Gateway) needsInput(ctx context.Context, rec audit.Record, pr policy.Request, res *mcp.CallToolResult,
	canAnswer bool) (*mcp.CallToolResult, string) {
	ids := make([]string, 0, len(res.InputRequests))
	for id := range res.InputRequests {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	denied := ""
	for _, id := range ids {
		r := rec
		r.ClientRequest = kindOf(res.InputRequests[id])
		pr.ClientRequest = r.ClientRequest
		dec, err := g.decider().Decide(ctx, pr)
		switch {
		case err != nil || !dec.Allowed():
			r.Decision, r.Rule, r.Status = string(policy.Deny), dec.Rule, audit.StatusDenied
			if err != nil {
				r.Rule = policy.DefaultDeny
			}
			if denied == "" {
				denied = r.Rule
			}
		case !canAnswer:
			r.Decision, r.Rule, r.Status = string(policy.Allow), dec.Rule, audit.StatusNotSent
			r.Reason = "client_protocol"
		default:
			r.Decision, r.Rule, r.Status = string(policy.Allow), dec.Rule, audit.StatusOK
		}
		g.write(r)
	}
	if denied != "" {
		return errorResult("denied by rule " + denied), denied
	}
	if !canAnswer {
		return errorResult("the upstream needs input from the client, which requires MCP 2026-07-28"), ""
	}
	res.RequestState = g.seal(sealedState{User: pr.Principal.User, Tool: rec.Tool, IDs: ids,
		Upstream: res.RequestState, Expires: time.Now().Add(stateTTL).Unix()})
	return res, ""
}

// clientCaps keeps the parts of the caller's declared capabilities that concern
// requests to it, for the upstream to see. Other parts, extensions included, stay here.
func clientCaps(meta mcp.Meta) mcp.Meta {
	caps, _ := meta[mcp.MetaKeyClientCapabilities].(map[string]any)
	out := map[string]any{}
	for _, k := range policy.ClientRequestKinds {
		if v, ok := caps[k]; ok {
			out[k] = v
		}
	}
	return mcp.Meta{mcp.MetaKeyClientCapabilities: out}
}

// canAnswer reports whether the caller speaks a revision with input-required results.
func canAnswer(req *mcp.CallToolRequest) bool {
	ss, ok := req.GetSession().(*mcp.ServerSession)
	if !ok || ss.InitializeParams() == nil {
		return false
	}
	return ss.InitializeParams().ProtocolVersion >= "2026-07-28"
}
