package coraza

import (
	"errors"
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
	binds, releases int
}

func (b *testPrivacyBridge) Bind(string, *http.Request) func() {
	b.binds++
	return func() { b.releases++ }
}
func (b *testPrivacyBridge) Redact(_ string, text string) string {
	if strings.Contains(text, b.secret) {
		return ""
	}
	return text
}

func TestManagedHeaderPrivacyRawDataProtectsEscapedErrorOutput(t *testing.T) {
	for _, secret := range []string{"accepted-key!", `accepted-"quote\slash!`} {
		core, logs := observer.New(zapcore.DebugLevel)
		bridge := &testPrivacyBridge{secret: secret}
		m := corazaModule{ManagedHeaderPrivacy: true, privacy: bridge, logger: zap.New(core), Directives: `SecRuleEngine DetectionOnly
SecRule REQUEST_HEADERS:X-Key "@unconditionalMatch" "id:900005,phase:1,pass,log,msg:'managed %{MATCHED_VAR}',logdata:'%{MATCHED_VAR}'"`}
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
	require.Equal(t, "", logs.All()[0].ContextMap()["error"])
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
