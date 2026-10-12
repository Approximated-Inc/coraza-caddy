// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddytest"
	"github.com/stretchr/testify/require"
)

// RFC 6455 section 1.3 sample nonce and its documented accept value.
const (
	wsTestKey    = "dGhlIHNhbXBsZSBub25jZQ=="
	wsTestAccept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
)

func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// writeWSFrame writes one short text frame. Clients must mask, servers must not.
func writeWSFrame(w io.Writer, payload string, masked bool) error {
	if len(payload) > 125 {
		return errors.New("test frames carry at most 125 bytes")
	}
	frame := []byte{0x81, byte(len(payload))}
	data := []byte(payload)
	if masked {
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		frame[1] |= 0x80
		frame = append(frame, key[:]...)
		for i := range data {
			data[i] ^= key[i%4]
		}
	}
	_, err := w.Write(append(frame, data...))
	return err
}

// readWSFrame reads one short frame and reports whether it was masked.
func readWSFrame(r *bufio.Reader) (string, bool, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", false, err
	}
	masked := head[1]&0x80 != 0
	n := int(head[1] & 0x7f)
	if n > 125 {
		return "", masked, errors.New("unexpected extended payload length")
	}
	var key [4]byte
	if masked {
		if _, err := io.ReadFull(r, key[:]); err != nil {
			return "", masked, err
		}
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", masked, err
	}
	if masked {
		for i := range data {
			data[i] ^= key[i%4]
		}
	}
	return string(data), masked, nil
}

// echoWSFrames echoes masked client frames unmasked until the peer goes away.
func echoWSFrames(conn net.Conn, r *bufio.Reader) {
	for {
		msg, masked, err := readWSFrame(r)
		if err != nil || !masked || writeWSFrame(conn, msg, false) != nil {
			return
		}
	}
}

// wsUpstream is a minimal origin: a WebSocket echo endpoint, a 103 Early
// Hints page, an event stream and a plain page. It records every request URI it receives.
type wsUpstream struct {
	*httptest.Server
	mu   sync.Mutex
	uris []string
}

func newWSUpstream(t *testing.T) *wsUpstream {
	t.Helper()
	u := &wsUpstream{}
	u.Server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.Close)
	return u
}

func (u *wsUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.uris = append(u.uris, r.URL.RequestURI())
	u.mu.Unlock()
	switch {
	case r.URL.Path == "/hints":
		w.Header().Set("Link", "</app.css>; rel=preload; as=style")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusTemporaryRedirect)
	case r.URL.Path == "/sse":
		// One event, flushed, then nothing until the client leaves or 2s
		// pass: a dropped flush holds the first event back that long.
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		_ = http.NewResponseController(w).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			_, _ = io.WriteString(w, "data: two\n\n")
		}
	case strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
		conn, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, err := fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", wsAccept(r.Header.Get("Sec-WebSocket-Key"))); err != nil {
			return
		}
		if brw.Flush() != nil {
			return
		}
		echoWSFrames(conn, brw.Reader)
	default:
		_, _ = io.WriteString(w, "hello-http")
	}
}

func (u *wsUpstream) received(marker string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	n := 0
	for _, uri := range u.uris {
		if strings.Contains(uri, marker) {
			n++
		}
	}
	return n
}

// dialWSUpgrade sends a browser-shaped opening handshake and returns the
// response with the connection positioned after its header block.
func dialWSUpgrade(t *testing.T, addr, target string, extra map[string]string) (*http.Response, net.Conn, *bufio.Reader, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: ws.example.test\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/129.0.0.0\r\nAccept-Encoding: gzip, deflate, br, zstd\r\nOrigin: http://ws.example.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", target, wsTestKey)
	for k, v := range extra {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	_, err = io.WriteString(conn, b.String())
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	return resp, conn, br, err
}

// requireWSEcho asserts a completed handshake and one echoed frame.
func requireWSEcho(t *testing.T, resp *http.Response, conn net.Conn, br *bufio.Reader, err error) {
	t.Helper()
	require.NoError(t, err, "no response to the WebSocket opening handshake")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	require.Equal(t, wsTestAccept, resp.Header.Get("Sec-WebSocket-Accept"))
	require.NoError(t, writeWSFrame(conn, "ping", true))
	msg, masked, err := readWSFrame(br)
	require.NoError(t, err)
	require.False(t, masked, "server frames must not be masked")
	require.Equal(t, "ping", msg)
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// TestWebSocketUpgradeThroughWAF runs real Caddy (waf > encode >
// reverse_proxy) in front of a WebSocket echo origin in both engine modes,
// with and without a deferred `header` op ahead of the WAF. The app puts one
// on every Fly cluster (Alt-Svc: clear), and Caddy then hands the WAF a
// writer that offers Unwrap but no Hijacker.
func TestWebSocketUpgradeThroughWAF(t *testing.T) {
	upstream := newWSUpstream(t)
	for _, tc := range []struct {
		name   string
		slug   string // URL-safe, and never a prefix of another case's slug
		engine string
		block  bool
		altSvc bool
	}{
		{"block", "block", "On", true, false},
		{"detect", "detect", "DetectionOnly", false, false},
		{"block behind deferred Alt-Svc", "altsvc-block", "On", true, true},
		{"detect behind deferred Alt-Svc", "altsvc-detect", "DetectionOnly", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := freeTCPPort(t)
			altSvc := ""
			if tc.altSvc {
				altSvc = "header >Alt-Svc clear"
			}
			tester := caddytest.NewTester(t)
			tester.InitServer(fmt.Sprintf(`{
				admin localhost:%d
				auto_https off
			}
			:%d {
				route {
				%s
				coraza_waf {
					directives `+"`"+`
						SecRuleEngine %s
						SecRequestBodyAccess On
						SecResponseBodyAccess On
						SecResponseBodyMimeType text/plain text/html
						SecRule ARGS|REQUEST_COOKIES "@detectXSS" "id:1001,phase:2,deny,status:403,log"
						SecRule ARGS|REQUEST_COOKIES "@detectSQLi" "id:1002,phase:2,deny,status:403,log"
					`+"`"+`
				}
				encode gzip
				reverse_proxy %s
				}
			}`, caddytest.Default.AdminPort, port, altSvc, tc.engine, upstream.Listener.Addr()), "caddyfile")
			addr := fmt.Sprintf("127.0.0.1:%d", port)

			t.Run("clean upgrade switches protocols and echoes", func(t *testing.T) {
				resp, conn, br, err := dialWSUpgrade(t, addr, "/ws?room=lobby-"+tc.slug, nil)
				requireWSEcho(t, resp, conn, br, err)
			})

			for _, attack := range []struct {
				name, marker, target string
				extra                map[string]string
			}{
				{"xss in query", "atk=xss-" + tc.slug, "/ws?atk=xss-" + tc.slug + "&q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", nil},
				{"sqli in cookie", "atk=sqli-" + tc.slug, "/ws?atk=sqli-" + tc.slug, map[string]string{"Cookie": "session=1' UNION SELECT password FROM users--"}},
			} {
				t.Run(attack.name, func(t *testing.T) {
					resp, conn, br, err := dialWSUpgrade(t, addr, attack.target, attack.extra)
					if tc.block {
						require.NoError(t, err)
						require.Equal(t, http.StatusForbidden, resp.StatusCode, "a request-phase deny must answer the upgrade with 403")
						require.Zero(t, upstream.received(attack.marker), "a blocked upgrade must never reach the origin")
						return
					}
					requireWSEcho(t, resp, conn, br, err)
					require.Equal(t, 1, upstream.received(attack.marker))
				})
			}

			t.Run("plain request is unaffected", func(t *testing.T) {
				res, err := tester.Client.Get("http://" + addr + "/page")
				require.NoError(t, err)
				defer res.Body.Close()
				body, err := io.ReadAll(res.Body)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, res.StatusCode)
				require.Equal(t, "hello-http", string(body))
				if tc.altSvc {
					require.Equal(t, "clear", res.Header.Get("Alt-Svc"), "the deferred header op must be in the chain")
				}
			})

			t.Run("streamed events are flushed as they are written", func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				type result struct {
					line string
					err  error
				}
				got := make(chan result, 1)
				go func() {
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/sse", nil)
					if err != nil {
						got <- result{err: err}
						return
					}
					req.Header.Set("Accept", "text/event-stream")
					res, err := http.DefaultClient.Do(req)
					if err != nil {
						got <- result{err: err}
						return
					}
					defer res.Body.Close()
					line, err := bufio.NewReader(res.Body).ReadString('\n')
					got <- result{line, err}
				}()
				select {
				case r := <-got:
					require.NoError(t, r.err)
					require.Equal(t, "data: one\n", r.line)
				case <-time.After(500 * time.Millisecond):
					t.Fatal("the first event did not arrive within 500ms; the origin's flush was dropped")
				}
			})

			t.Run("103 early hints still precede the final status", func(t *testing.T) {
				var codes []int
				var link string
				trace := &httptrace.ClientTrace{Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
					codes = append(codes, code)
					link = h.Get("Link")
					return nil
				}}
				req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, "http://"+addr+"/hints", nil)
				require.NoError(t, err)
				client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				res, err := client.Do(req)
				require.NoError(t, err)
				defer res.Body.Close()
				require.Equal(t, []int{http.StatusEarlyHints}, codes)
				require.Equal(t, "</app.css>; rel=preload; as=style", link)
				require.Equal(t, http.StatusTemporaryRedirect, res.StatusCode)
				require.Equal(t, "/login", res.Header.Get("Location"))
			})
		})
	}
}
