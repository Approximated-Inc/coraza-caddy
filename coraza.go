// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
	"go.uber.org/zap"
)

// wafPool is a process-global pool that allows WAF instances to be shared
// across Caddy config reloads. When two consecutive configs use the same
// WAF configuration, the pool returns the existing WAF instead of building
// a new one, saving both memory and CPU.
var wafPool = caddy.NewUsagePool()

func init() {
	caddy.RegisterModule(corazaModule{})
	httpcaddyfile.RegisterHandlerDirective("coraza_waf", parseCaddyfile)
}

// pooledWAF wraps a coraza.WAF so it can be stored in a caddy.UsagePool.
// It implements caddy.Destructor so the pool can clean it up when all
// references are released.
type pooledWAF struct {
	waf coraza.WAF
}

func (p *pooledWAF) Destruct() error {
	var err error
	if c, ok := p.waf.(io.Closer); ok {
		if cerr := c.Close(); cerr != nil {
			err = fmt.Errorf("closing WAF: %w", cerr)
		}
	}
	p.waf = nil
	return err
}

// corazaModule is a Web Application Firewall implementation for Caddy.
type corazaModule struct {
	// deprecated
	Include              []string `json:"include"`
	Directives           string   `json:"directives"`
	LoadOWASPCRS         bool     `json:"load_owasp_crs"`
	ManagedHeaderPrivacy bool     `json:"managed_header_privacy,omitempty"`
	privacy              managedHeaderPrivacyBridge

	logger  *zap.Logger
	waf     coraza.WAF
	poolKey string
}

// CaddyModule returns the Caddy module information.
func (corazaModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(corazaModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *corazaModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	if m.ManagedHeaderPrivacy {
		module, err := caddy.GetModule("apx.coraza_privacy")
		if err != nil {
			return errors.New("managed Header privacy module unavailable")
		}
		var ok bool
		m.privacy, ok = module.New().(managedHeaderPrivacyBridge)
		if !ok {
			return errors.New("invalid managed Header privacy bridge")
		}
	}
	m.poolKey = m.computePoolKey()

	val, loaded, err := wafPool.LoadOrNew(m.poolKey, func() (caddy.Destructor, error) {
		waf, err := m.buildWAF()
		if err != nil {
			return nil, err
		}
		return &pooledWAF{waf: waf}, nil
	})
	if err != nil {
		return err
	}

	m.waf = val.(*pooledWAF).waf
	if loaded {
		m.logger.Info("reusing existing WAF instance from pool")
	}
	return nil
}

// buildWAF creates a new coraza.WAF from the module's configuration.
func (m *corazaModule) buildWAF() (coraza.WAF, error) {
	callback := newErrorCb(m.logger)
	debugLogger := newLogger(m.logger)
	if m.ManagedHeaderPrivacy {
		callback = newErrorCb(m.logger, m.privacy)
		debugLogger = newLogger(zap.NewNop())
	}
	config := coraza.NewWAFConfig().WithErrorCallback(callback).WithDebugLogger(debugLogger)

	if m.LoadOWASPCRS {
		config = config.WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS))
	}

	if m.Directives != "" {
		config = config.WithDirectives(m.Directives)
	}

	if len(m.Include) > 0 {
		m.logger.Warn("'include' field is deprecated, please use the Include directive inside 'directives' field instead")
		for _, file := range m.Include {
			if strings.Contains(file, "*") {
				m.logger.Debug("Preparing to expand glob", zap.String("pattern", file))
				// we get files as expandables globs (with wildcard patterns)
				fs, err := filepath.Glob(file)
				if err != nil {
					return nil, err
				}
				m.logger.Debug("Glob expanded", zap.String("pattern", file), zap.Strings("files", fs))
				for _, f := range fs {
					config = config.WithDirectivesFromFile(f)
				}
			} else {
				m.logger.Debug("File was not a pattern, compiling it", zap.String("file", file))
				config = config.WithDirectivesFromFile(file)
			}
		}
	}

	if m.ManagedHeaderPrivacy {
		config = config.WithDirectives(`SecComponentSignature "APX_MANAGED_HEADER_PRIVACY/1"`)
	}
	return coraza.NewWAF(config)
}

// computePoolKey returns a deterministic key derived from the configuration
// fields that affect WAF construction. Two modules with identical configs
// will produce the same key, enabling WAF reuse across reloads.
func (m *corazaModule) computePoolKey() string {
	h := sha256.New()
	h.Write([]byte(m.Directives))
	if m.ManagedHeaderPrivacy {
		h.Write([]byte("managed-header-privacy/1"))
	}
	h.Write([]byte{0}) // separator

	sorted := make([]string, len(m.Include))
	copy(sorted, m.Include)
	sort.Strings(sorted)
	for _, inc := range sorted {
		h.Write([]byte(inc))
		h.Write([]byte{0})
	}

	if m.LoadOWASPCRS {
		h.Write([]byte("crs"))
	}
	return fmt.Sprintf("coraza-waf-%x", h.Sum(nil))
}

// Validate implements caddy.Validator.
func (m *corazaModule) Validate() error {
	return nil
}

// Cleanup implements caddy.CleanerUpper.
func (m *corazaModule) Cleanup() error {
	_, err := wafPool.Delete(m.poolKey)
	return err
}

var errInterruptionTriggered = errors.New("interruption triggered")

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m corazaModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	id := randomString(16)
	if m.ManagedHeaderPrivacy {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return errors.New("WAF transaction identity unavailable")
		}
		id = hex.EncodeToString(bytes)
	}
	release := func() {}
	if m.ManagedHeaderPrivacy && m.privacy != nil {
		release = m.privacy.Bind(id, r)
	}
	defer release()
	tx := m.waf.NewTransactionWithID(id)
	defer func() {
		if err := tx.Close(); err != nil {
			m.logger.Warn("Failed to close the transaction", zap.String("tx_id", tx.ID()), zap.String("error", m.privateText(id, err.Error())))
		}
	}()
	defer tx.ProcessLogging()

	// Early return, Coraza is not going to process any rule
	if tx.IsRuleEngineOff() {
		// response writer is not going to be wrapped, but used as-is
		// to generate the response
		return m.privateError(id, next.ServeHTTP(w, r))
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	repl.Set("http.transaction_id", id)

	server := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	caddyhttp.PrepareRequest(r, repl, w, server)

	// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
	// ProcessRequestHeaders and ProcessRequestBody.
	// It fails if any of these functions returns an error and it stops on interruption.
	if it, err := processRequest(tx, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: http.StatusInternalServerError,
			ID:         tx.ID(),
			Err:        m.privateError(id, err),
		}
	} else if it != nil {
		m.logger.Error("WAF rule violation detected",
			zap.String("hostname", m.privateText(id, r.Host)),
			zap.String("uri", m.privateText(id, r.RequestURI)),
			zap.String("client_ip", m.privateText(id, r.RemoteAddr)),
			zap.String("unique_id", tx.ID()),
		)
		return caddyhttp.HandlerError{
			StatusCode: obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK),
			ID:         tx.ID(),
			Err:        errInterruptionTriggered,
		}
	}

	ww, processResponse := wrap(w, r, tx)

	// We continue with the other middlewares by catching the response
	if err := next.ServeHTTP(ww, r); err != nil {
		return m.privateError(id, err)
	}

	return m.privateError(id, processResponse(tx, r))
}

// Unmarshal Caddyfile implements caddyfile.Unmarshaler.
func (m *corazaModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token following filter")
	}
	m.Include = []string{}
	for d.NextBlock(0) {
		key := d.Val()
		switch key {
		case "load_owasp_crs":
			if d.NextArg() {
				return d.ArgErr()
			}
			m.LoadOWASPCRS = true
		case "directives", "include":
			var value string
			if !d.Args(&value) {
				// not enough args
				return d.ArgErr()
			}

			if d.NextArg() {
				// too many args
				return d.ArgErr()
			}

			switch key {
			case "include":
				m.Include = append(m.Include, value)
			case "directives":
				m.Directives = value
			}
		default:
			return d.Errf("invalid key %q", key)
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m corazaModule
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

func newErrorCb(logger *zap.Logger, privacy ...managedHeaderPrivacyBridge) func(types.MatchedRule) {
	return func(mr types.MatchedRule) {
		logMsg := mr.ErrorLog()
		if len(privacy) > 0 {
			if privacy[0] == nil {
				logMsg = ""
			} else {
				id := mr.TransactionID()
				sensitive := privacy[0].Redact(id, mr.Message()) != mr.Message() || privacy[0].Redact(id, mr.Data()) != mr.Data()
				for _, match := range mr.MatchedDatas() {
					sensitive = sensitive || privacy[0].Redact(id, match.Value()) != match.Value() || privacy[0].Redact(id, match.Message()) != match.Message() || privacy[0].Redact(id, match.Data()) != match.Data()
				}
				if sensitive {
					logMsg = ""
				} else {
					logMsg = privacy[0].Redact(id, logMsg)
				}
			}
		}
		switch mr.Rule().Severity() {
		case types.RuleSeverityEmergency,
			types.RuleSeverityAlert,
			types.RuleSeverityCritical,
			types.RuleSeverityError:
			logger.Error(logMsg)
		case types.RuleSeverityWarning:
			logger.Warn(logMsg)
		case types.RuleSeverityNotice:
			logger.Info(logMsg)
		case types.RuleSeverityInfo:
			logger.Info(logMsg)
		case types.RuleSeverityDebug:
			logger.Debug(logMsg)
		default:
			logger.Warn(logMsg)
		}
	}
}

// The bridge is discovered through Caddy to keep the connector independent of
// the stats package. It is private state, never exemption authority.
type managedHeaderPrivacyBridge interface {
	Bind(string, *http.Request) func()
	Redact(string, string) string
}

func (m corazaModule) privateText(id, text string) string {
	if !m.ManagedHeaderPrivacy {
		return text
	}
	if m.privacy == nil {
		return ""
	}
	return m.privacy.Redact(id, text)
}
func (m corazaModule) privateError(id string, err error) error {
	if err == nil || !m.ManagedHeaderPrivacy {
		return err
	}
	text := m.privateText(id, err.Error())
	// An empty outer representation may still unwrap to a sensitive cause.
	// Determine request masking independently before preserving that chain.
	masking := m.privateText(id, "managed-header-error-privacy") == ""
	if !masking && text == err.Error() {
		return err
	}
	var handlerError caddyhttp.HandlerError
	if errors.As(err, &handlerError) {
		if handlerError.Err != nil {
			handlerError.Err = errors.New(m.privateText(id, handlerError.Err.Error()))
		}
		if _, direct := err.(caddyhttp.HandlerError); direct {
			return handlerError
		}
		return privateWrappedHandlerError{text: text, cause: handlerError}
	}
	return errors.New(text)
}

// Keep an originally wrapped HandlerError wrapped: Caddy dispatch uses
// errors.As, while placeholder/fallback code deliberately checks the direct type.
// Its only unwrap target is the sanitized copy, never the original error chain.
type privateWrappedHandlerError struct {
	text  string
	cause caddyhttp.HandlerError
}

func (e privateWrappedHandlerError) Error() string { return e.text }
func (e privateWrappedHandlerError) Unwrap() error { return e.cause }

// Interface guards
var (
	_ caddy.Provisioner           = (*corazaModule)(nil)
	_ caddy.Validator             = (*corazaModule)(nil)
	_ caddy.CleanerUpper          = (*corazaModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*corazaModule)(nil)
	_ caddyfile.Unmarshaler       = (*corazaModule)(nil)
)
