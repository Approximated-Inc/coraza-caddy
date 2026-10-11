package coraza

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// statsClassification mirrors how apx-caddy-stats reads a returned error
// (handler.go blockReason/noAvailableUpstreams, upstream_failure.go's typed
// upstreamFailureReason path). Masking must not change any of it.
type statsClassification struct {
	block, reason string
	noUpstream    bool
	status        int
}

func classifyLikeStats(err error) statsClassification {
	var c statsClassification
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) {
		return c
	}
	c.status = he.StatusCode
	if strings.Contains(he.Error(), "interruption triggered") {
		c.block = "waf"
	} else if he.StatusCode == http.StatusTooManyRequests {
		c.block = "rate_limit"
	}
	c.noUpstream = he.StatusCode == 503 && he.Err != nil && he.Err.Error() == "no upstreams available"
	if c.noUpstream {
		c.reason = "no_upstreams_available"
		return c
	}
	if errors.Is(err, context.Canceled) {
		return c
	}
	cause := err
	if he.Err != nil {
		cause = he.Err
	}
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verification *tls.CertificateVerificationError
	var dns *net.DNSError
	var op *net.OpError
	var ne net.Error
	switch {
	case errors.As(cause, &authority) || errors.As(cause, &invalid) || errors.As(cause, &hostname) || errors.As(cause, &verification):
		c.reason = "tls_certificate_error"
	case errors.As(cause, &dns):
		c.reason = "dns_error"
		if dns.Timeout() {
			c.reason = "dns_timeout"
		}
	case errors.Is(cause, syscall.ECONNRESET):
		c.reason = "connection_reset"
	case errors.Is(cause, io.EOF) || errors.Is(cause, io.ErrUnexpectedEOF):
		c.reason = "upstream_eof"
	case cause.Error() == "net/http: timeout awaiting response headers":
		c.reason = "response_header_timeout"
	case errors.As(cause, &op) && op.Op == "write":
		c.reason = "request_write_error"
		if errors.As(op, &ne) && ne.Timeout() {
			c.reason = "request_write_timeout"
		}
	default:
		c.reason = "unknown"
	}
	return c
}

const classificationSecret = "managed-classification-key!"

func maskedModule(t *testing.T, directives string) corazaModule {
	t.Helper()
	m := corazaModule{ManagedHeaderPrivacy: true, privacy: &testPrivacyBridge{maskAll: true}, logger: zap.NewNop(), Directives: directives}
	waf, err := m.buildWAF()
	require.NoError(t, err)
	m.waf = waf
	return m
}

func replacerRequest() *http.Request {
	request := httptest.NewRequest("GET", "/", nil)
	ctx := context.WithValue(request.Context(), caddy.ReplacerCtxKey, caddy.NewReplacer())
	return request.WithContext(context.WithValue(ctx, caddyhttp.ServerCtxKey, &caddyhttp.Server{}))
}

func requireNoSecret(t *testing.T, err error) {
	t.Helper()
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		require.False(t, strings.Contains(cause.Error(), classificationSecret), "masked error text retained the managed value")
	}
	var he caddyhttp.HandlerError
	if errors.As(err, &he) {
		require.False(t, strings.Contains(he.Error(), classificationSecret), "masked HandlerError retained the managed value")
	}
	require.False(t, strings.Contains(fmt.Sprintf("%+v", err), classificationSecret), "masked error formatting retained the managed value")
}

func TestManagedHeaderPrivacyMaskedResponseInterruptionStaysWAFBlock(t *testing.T) {
	m := maskedModule(t, `SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_BODY "@contains `+classificationSecret+`" "id:900101,phase:4,deny,status:403,log"`)
	request := replacerRequest()
	request.Header.Set("X-Managed", classificationSecret)
	actual := m.ServeHTTP(httptest.NewRecorder(), request, caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error {
		w.Header().Set("Content-Type", "text/plain")
		_, err := w.Write([]byte("echo " + classificationSecret))
		return err
	}))
	require.Error(t, actual)
	got := classifyLikeStats(actual)
	require.Equal(t, "waf", got.block, "masked response-phase interruption lost its WAF block classification")
	require.Equal(t, 403, got.status)
	require.True(t, errors.Is(actual, errInterruptionTriggered), "masked interruption lost its sentinel")
	requireNoSecret(t, actual)
}

func TestManagedHeaderPrivacyMaskedErrorsClassifyLikeUnmasked(t *testing.T) {
	// Caddy's own no-upstream sentinel is unexported; this is its exact value.
	noUpstream := fmt.Errorf("no upstreams available")
	writeTimeout := &net.OpError{Op: "write", Net: "unix", Addr: &net.UnixAddr{Name: classificationSecret, Net: "unix"}, Err: os.ErrDeadlineExceeded}
	cases := map[string]struct {
		handler caddyhttp.HandlerError
		want    statsClassification
	}{
		"no upstream":       {caddyhttp.Error(503, noUpstream), statsClassification{status: 503, noUpstream: true, reason: "no_upstreams_available"}},
		"waf":               {caddyhttp.HandlerError{StatusCode: 403, Err: errInterruptionTriggered}, statsClassification{status: 403, block: "waf", reason: "unknown"}},
		"rate limit":        {caddyhttp.Error(429, nil), statsClassification{status: 429, block: "rate_limit", reason: "unknown"}},
		"certificate":       {caddyhttp.Error(502, &tls.CertificateVerificationError{Err: x509.HostnameError{Certificate: &x509.Certificate{}, Host: classificationSecret}}), statsClassification{status: 502, reason: "tls_certificate_error"}},
		"unknown authority": {caddyhttp.Error(502, fmt.Errorf("%s: %w", classificationSecret, x509.UnknownAuthorityError{})), statsClassification{status: 502, reason: "tls_certificate_error"}},
		"dns":               {caddyhttp.Error(502, &net.DNSError{Err: "no such host", Name: classificationSecret}), statsClassification{status: 502, reason: "dns_error"}},
		"dns timeout":       {caddyhttp.Error(504, &net.DNSError{Err: "i/o timeout", Name: classificationSecret, IsTimeout: true}), statsClassification{status: 504, reason: "dns_timeout"}},
		"reset":             {caddyhttp.Error(502, &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: classificationSecret, Err: syscall.ECONNRESET}}), statsClassification{status: 502, reason: "connection_reset"}},
		"eof":               {caddyhttp.Error(502, fmt.Errorf("%s: %w", classificationSecret, io.EOF)), statsClassification{status: 502, reason: "upstream_eof"}},
		"unexpected eof":    {caddyhttp.Error(502, fmt.Errorf("%s: %w", classificationSecret, io.ErrUnexpectedEOF)), statsClassification{status: 502, reason: "upstream_eof"}},
		"header timeout":    {caddyhttp.Error(504, errors.New("net/http: timeout awaiting response headers")), statsClassification{status: 504, reason: "response_header_timeout"}},
		"write timeout":     {caddyhttp.Error(504, writeTimeout), statsClassification{status: 504, reason: "request_write_timeout"}},
		"write error":       {caddyhttp.Error(502, &net.OpError{Op: "write", Net: "tcp", Err: errors.New(classificationSecret)}), statsClassification{status: 502, reason: "request_write_error"}},
		"canceled":          {caddyhttp.Error(499, fmt.Errorf("%s: %w", classificationSecret, context.Canceled)), statsClassification{status: 499}},
		"private":           {caddyhttp.Error(502, errors.New(classificationSecret)), statsClassification{status: 502, reason: "unknown"}},
	}
	for name, tc := range cases {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s-wrapped%t", name, wrapped), func(t *testing.T) {
				var downstream error = tc.handler
				if wrapped {
					downstream = fmt.Errorf("%s wrapper: %w", classificationSecret, tc.handler)
				}
				require.Equal(t, tc.want, classifyLikeStats(downstream), "fixture does not classify as expected unmasked")
				m := maskedModule(t, "SecRuleEngine On")
				actual := m.ServeHTTP(httptest.NewRecorder(), replacerRequest(), caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return downstream }))
				require.Equal(t, tc.want, classifyLikeStats(actual), "masked error classifies differently from unmasked")
				requireNoSecret(t, actual)
				_, direct := actual.(caddyhttp.HandlerError)
				require.Equal(t, !wrapped, direct, "direct versus wrapped Caddy dispatch changed")
				if name == "no upstream" {
					require.True(t, errors.Is(actual, noUpstream), "Caddy's errors.Is(errNoUpstream) retry check no longer matches")
				}
			})
		}
	}
}
