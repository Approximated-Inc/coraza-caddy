package coraza

import (
	"context"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	corazaWAF "github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

type testPrivacyBridge struct {
	secret          string
	maskAll         bool
	binds, releases int
}

func (b *testPrivacyBridge) Bind(string, *http.Request) func() {
	b.binds++
	return func() { b.releases++ }
}
func (b *testPrivacyBridge) Redact(_ string, text string) string {
	if b.maskAll || strings.Contains(text, b.secret) {
		return ""
	}
	return text
}

func TestManagedHeaderPrivacyRawDataProtectsEscapedErrorOutput(t *testing.T) {
	for _, secret := range []string{"accepted-key!", `accepted-"quote\slash!`, "accepted-encoded-key%21"} {
		core, logs := observer.New(zapcore.DebugLevel)
		bridge := &testPrivacyBridge{secret: secret, maskAll: true}
		m := corazaModule{ManagedHeaderPrivacy: true, privacy: bridge, logger: zap.New(core), Directives: `SecRuleEngine DetectionOnly
SecRule REQUEST_HEADERS:X-Key "@validateByteRange 32,34,38,42-59,61,65-90,95,97-122" "id:920274,phase:1,block,t:none,t:urlDecodeUni,log,msg:'Invalid character in request headers (outside of very strict set)',logdata:'%{MATCHED_VAR_NAME}=%{MATCHED_VAR}'"`}
		waf, err := m.buildWAF()
		require.NoError(t, err)
		tx := waf.NewTransactionWithID("private-error-test")
		tx.AddRequestHeader("X-Key", secret)
		tx.ProcessRequestHeaders()
		tx.ProcessLogging()
		require.NoError(t, tx.Close())
		require.Positive(t, logs.Len())
		for _, entry := range logs.All() {
			require.True(t, entry.Message == "", "sensitive error text was retained")
		}
	}
}

func TestManagedHeaderPrivacyDeferCleanupOnDownstreamAndCloseErrors(t *testing.T) {
	waf, err := corazaWAF.NewWAF(corazaWAF.NewWAFConfig().WithDirectives("SecRuleEngine Off"))
	require.NoError(t, err)
	bridge := &testPrivacyBridge{secret: "private-close-key!"}
	core, logs := observer.New(zapcore.WarnLevel)
	m := corazaModule{ManagedHeaderPrivacy: true, privacy: bridge, logger: zap.New(core), waf: &mockWAF{real: waf, closeErr: errors.New(bridge.secret)}}
	err = m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return errors.New(bridge.secret) }))
	require.Error(t, err)
	require.True(t, !strings.Contains(err.Error(), bridge.secret), "downstream error retained credential")
	require.Equal(t, 1, bridge.binds)
	require.Equal(t, 1, bridge.releases)
	require.Equal(t, 1, logs.Len())
	privateCloseError, ok := logs.All()[0].ContextMap()["error"].(string)
	require.True(t, ok && privateCloseError == "", "close error text retained sensitive material")
}

func TestManagedHeaderPrivacyPoolAndDebugBoundary(t *testing.T) {
	a := corazaModule{Directives: "SecRuleEngine Off"}
	b := a
	b.ManagedHeaderPrivacy = true
	require.NotEqual(t, a.computePoolKey(), b.computePoolKey())
	core, logs := observer.New(zapcore.DebugLevel)
	b.logger = zap.New(core)
	b.privacy = &testPrivacyBridge{secret: "debug-key!"}
	b.Directives = `SecRuleEngine DetectionOnly
SecDebugLogLevel 9
SecRule REQUEST_HEADERS:X-Key "@unconditionalMatch" "id:900006,phase:1,pass,nolog"`
	waf, err := b.buildWAF()
	require.NoError(t, err)
	tx := waf.NewTransactionWithID("private-debug-test")
	tx.AddRequestHeader("X-Key", "debug-key!")
	tx.ProcessRequestHeaders()
	tx.ProcessLogging()
	require.NoError(t, tx.Close())
	require.Zero(t, logs.Len(), "managed mode must not emit unbound debug payloads")
}

func TestManagedHeaderPrivacyPreservesHandlerError(t *testing.T) {
	for _, status := range []int{403, 502} {
		for _, wrapped := range []bool{false, true} {
			original := caddyhttp.HandlerError{StatusCode: status, ID: "fixture-id", Trace: "fixture-trace", Err: errors.New("typed-private-key!")}
			var downstream error = original
			if wrapped {
				downstream = fmt.Errorf("private wrapper: %w", original)
			}
			waf, err := corazaWAF.NewWAF(corazaWAF.NewWAFConfig().WithDirectives("SecRuleEngine Off"))
			require.NoError(t, err)
			bridge := &testPrivacyBridge{maskAll: true}
			m := corazaModule{ManagedHeaderPrivacy: true, privacy: bridge, logger: zap.NewNop(), waf: waf}
			actual := m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return downstream }))
			require.Equal(t, 1, bridge.binds)
			require.Equal(t, 1, bridge.releases)
			_, direct := actual.(caddyhttp.HandlerError)
			require.Equal(t, !wrapped, direct, "direct versus wrapped Caddy dispatch changed")
			var preserved caddyhttp.HandlerError
			require.True(t, errors.As(actual, &preserved), "errors.As lost Caddy HandlerError")
			require.Equal(t, status, preserved.StatusCode)
			require.Equal(t, original.ID, preserved.ID)
			require.Equal(t, original.Trace, preserved.Trace)
			require.True(t, preserved.Err != nil && preserved.Err.Error() == "", "underlying error retained sensitive text")
			for cause := actual; cause != nil; cause = errors.Unwrap(cause) {
				require.False(t, strings.Contains(cause.Error(), "typed-private-key!"), "unwrap retained sensitive text")
			}
			request := httptest.NewRequest("GET", "/", nil)
			request = request.WithContext(context.WithValue(request.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
			request = (*caddyhttp.HTTPErrorConfig)(nil).WithError(request, actual)
			repl := request.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			code, present := repl.Get("http.error.status_code")
			require.Equal(t, !wrapped, present, "wrapped placeholder presence changed")
			if wrapped {
				for _, key := range []string{"http.error.id", "http.error.trace", "http.error.message"} {
					_, present := repl.Get(key)
					require.False(t, present, "wrapped error gained direct placeholders")
				}
			} else {
				require.Equal(t, status, code)
				id, _ := repl.Get("http.error.id")
				require.Equal(t, original.ID, id)
				trace, _ := repl.Get("http.error.trace")
				require.Equal(t, original.Trace, trace)
				message, _ := repl.Get("http.error.message")
				require.True(t, message == "", "error placeholder retained sensitive text")
			}
		}
	}
}

func TestManagedHeaderPrivacyOrdinaryAndDisabledErrorIdentity(t *testing.T) {
	sentinel := errors.New("ordinary cause")
	for _, enabled := range []bool{false, true} {
		m := corazaModule{ManagedHeaderPrivacy: enabled, privacy: &testPrivacyBridge{secret: "not-supplied-key!"}}
		original := caddyhttp.HandlerError{StatusCode: 403, ID: "ordinary-id", Trace: "ordinary-trace", Err: sentinel}
		actual := m.privateError("ordinary", original)
		preserved, ok := actual.(caddyhttp.HandlerError)
		require.True(t, ok && preserved == original, "ordinary HandlerError identity changed")
		require.True(t, errors.Is(actual, sentinel), "ordinary cause semantics changed")
		wrapped := fmt.Errorf("ordinary wrapper: %w", original)
		require.True(t, m.privateError("ordinary", wrapped) == wrapped, "ordinary wrapped error identity changed")
		require.Nil(t, m.privateError("ordinary", nil))
	}
}

type emptyPrivacyError struct{ cause error }

func (e emptyPrivacyError) Error() string { return "" }
func (e emptyPrivacyError) Unwrap() error { return e.cause }

func TestManagedHeaderPrivacyEmptyOuterHandlerCause(t *testing.T) {
	for _, status := range []int{403, 502} {
		for _, nilCause := range []bool{false, true} {
			for _, mode := range []struct {
				enabled, masked bool
			}{{true, true}, {true, false}, {false, true}} {
				t.Run(fmt.Sprintf("status%d-nil%t-enabled%t-masked%t", status, nilCause, mode.enabled, mode.masked), func(t *testing.T) {
					var cause error
					if !nilCause {
						cause = errors.New("empty-outer-private-key!")
					}
					handler := caddyhttp.HandlerError{StatusCode: status, ID: "empty-id", Trace: "empty-trace", Err: cause}
					original := emptyPrivacyError{cause: handler}
					waf, err := corazaWAF.NewWAF(corazaWAF.NewWAFConfig().WithDirectives("SecRuleEngine Off"))
					require.NoError(t, err)
					bridge := &testPrivacyBridge{secret: "absent-test-secret", maskAll: mode.masked}
					m := corazaModule{ManagedHeaderPrivacy: mode.enabled, privacy: bridge, logger: zap.NewNop(), waf: waf}
					actual := m.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return original }))
					expectedBinds := 0
					if mode.enabled {
						expectedBinds = 1
					}
					require.Equal(t, expectedBinds, bridge.binds)
					require.Equal(t, expectedBinds, bridge.releases)
					require.True(t, actual != nil && actual.Error() == "", "empty outer representation changed")
					_, direct := actual.(caddyhttp.HandlerError)
					require.False(t, direct, "empty wrapped error gained direct Caddy dispatch")
					var preserved caddyhttp.HandlerError
					require.True(t, errors.As(actual, &preserved), "empty wrapper lost Caddy errors.As metadata")
					require.Equal(t, status, preserved.StatusCode)
					require.Equal(t, handler.ID, preserved.ID)
					require.Equal(t, handler.Trace, preserved.Trace)
					if mode.enabled && mode.masked {
						if nilCause {
							require.Nil(t, preserved.Err, "nil HandlerError cause changed")
						} else {
							require.True(t, preserved.Err != nil && preserved.Err.Error() == "", "empty outer error retained a sensitive HandlerError cause")
							for inner := actual; inner != nil; inner = errors.Unwrap(inner) {
								require.False(t, strings.Contains(inner.Error(), "empty-outer-private-key!"), "empty wrapper unwrap retained sensitive text")
							}
						}
					} else {
						require.True(t, actual == original, "ordinary or disabled empty wrapper identity changed")
						require.True(t, preserved.Err == cause, "ordinary or disabled cause identity changed")
						if cause != nil {
							require.True(t, errors.Is(actual, cause), "ordinary or disabled errors.Is changed")
						}
					}
					request := httptest.NewRequest("GET", "/", nil)
					request = request.WithContext(context.WithValue(request.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer()))
					request = (*caddyhttp.HTTPErrorConfig)(nil).WithError(request, actual)
					repl := request.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
					for _, key := range []string{"http.error.status_code", "http.error.id", "http.error.trace", "http.error.message"} {
						_, present := repl.Get(key)
						require.False(t, present, "empty wrapped error gained direct placeholders")
					}
				})
			}
		}
	}
}
