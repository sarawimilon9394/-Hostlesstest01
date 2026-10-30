package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed bermuda.jpg
var portalPrismJPEG []byte

const (
	defaultPathXH = "/api/v1/sync"
	defaultPathWS = "/api/v1/live"
	defaultPathTR = "/api/v1/gateway"

	defaultHealthPath = "/healthz"
	legacyHealthPath  = "/.well-known/hc-5b1e7c"
	portalSessionName = "__bp_sess"

	openrestyServerToken = "openresty"

	openrestyIndexLastModified = "Fri, 06 Aug 2021 21:32:34 GMT"
	openrestyIndexETag         = "\"610daa72-449\""

	openresty50xLastModified = openrestyIndexLastModified
	openresty50xETag         = "\"610daa72-3d6\""

	defaultProxyBufferSize    = 64 * 1024
	defaultTransportBufSize   = 64 * 1024
	compactProxyBufferSize    = 32 * 1024
	compactTransportBufSize   = 32 * 1024
	defaultBufferPoolCapacity = 64
	compactBufferPoolCapacity = 24
	halfCloseGrace            = 25 * time.Second
	backendDialTimeout        = 5 * time.Second
	backendHandshakeTimeout   = 5 * time.Second
	tunnelDrainPollInterval   = 50 * time.Millisecond

	xPaddingMinBytes        = 100
	xPaddingMaxBytes        = 1000
	xPaddingObfsMaxBytes    = 500
	xPaddingDefaultBytes    = 256
	internalTransformHeader = "X-Bermuda-Mode"
	base62Chars             = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	openrestyModTime = time.Date(2021, time.August, 6, 21, 32, 34, 0, time.UTC)
	xPaddingRepeatX  = strings.Repeat("X", xPaddingMaxBytes)
)

const openrestyWelcomeHTML = "<!DOCTYPE html>\n" +
	"<html>\n" +
	"<head>\n" +
	"<meta content=\"text/html;charset=utf-8\" http-equiv=\"Content-Type\">\n" +
	"<meta content=\"utf-8\" http-equiv=\"encoding\">\n" +
	"<title>Welcome to OpenResty!</title>\n" +
	"<style>\n" +
	"    body {\n" +
	"        width: 35em;\n" +
	"        margin: 0 auto;\n" +
	"        font-family: Tahoma, Verdana, Arial, sans-serif;\n" +
	"    }\n" +
	"</style>\n" +
	"</head>\n" +
	"<body>\n" +
	"<h1>Welcome to OpenResty!</h1>\n" +
	"<p>If you see this page, the OpenResty web platform is successfully installed and\n" +
	"working. Further configuration is required.</p>\n" +
	"\n" +
	"<p>For online documentation and support please refer to our\n" +
	"<a href=\"https://openresty.org/\">openresty.org</a> site<br/>\n" +
	"Commercial support is available at\n" +
	"<a href=\"https://openresty.com/\">openresty.com</a>.</p>\n" +
	"<p>We have articles on troubleshooting issues like <a href=\"https://blog.openresty.com/en/lua-cpu-flame-graph/?src=wb\">high CPU usage</a> and\n" +
	"<a href=\"https://blog.openresty.com/en/how-or-alloc-mem/\">large memory usage</a> on <a href=\"https://blog.openresty.com/\">our official blog site</a>.\n" +
	"<p><em>Thank you for flying <a href=\"https://openresty.org/\">OpenResty</a>.</em></p>\n" +
	"</body>\n" +
	"</html>\n"

const openresty50xHTML = "<!DOCTYPE html>\n" +
	"<html>\n" +
	"<head>\n" +
	"<meta content=\"text/html;charset=utf-8\" http-equiv=\"Content-Type\">\n" +
	"<meta content=\"utf-8\" http-equiv=\"encoding\">\n" +
	"<title>Error</title>\n" +
	"<style>\n" +
	"    body {\n" +
	"        width: 35em;\n" +
	"        margin: 0 auto;\n" +
	"        font-family: Tahoma, Verdana, Arial, sans-serif;\n" +
	"    }\n" +
	"</style>\n" +
	"</head>\n" +
	"<body>\n" +
	"<h1>An error occurred.</h1>\n" +
	"<p>Sorry, the page you are looking for is currently unavailable.<br/>\n" +
	"Please try again later.</p>\n" +
	"<p>If you are the system administrator of this resource then you should check\n" +
	"the <a href=\"http://nginx.org/r/error_log\">error log</a> for details.</p>\n" +
	"<p>We have articles on troubleshooting issues like <a href=\"https://blog.openresty.com/en/lua-cpu-flame-graph/?src=wb\">high CPU usage</a> and\n" +
	"<a href=\"https://blog.openresty.com/en/how-or-alloc-mem/\">large memory usage</a> on <a href=\"https://blog.openresty.com/\">our official blog site</a>.\n" +
	"<p><em>Faithfully yours, <a href=\"https://openresty.org/\">OpenResty</a>.</em></p>\n" +
	"</body>\n" +
	"</html>\n"

const openresty404HTML = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>openresty</center>\r\n</body>\r\n</html>\r\n"
const openresty405HTML = "<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>openresty</center>\r\n</body>\r\n</html>\r\n"

const portalPanelTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>BERMUDA PORTAL</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  html,body{width:100%;height:100%;background:#000000;color:#ffffff;font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","Segoe UI",Roboto,sans-serif;overflow:hidden;-webkit-font-smoothing:antialiased;user-select:none}
  body{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
  .stage{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:28px;width:100%;max-width:460px}
  .prism-wrap{position:relative;width:min(380px,82vw);aspect-ratio:1/1;display:flex;align-items:center;justify-content:center}
  .prism-img{width:100%;height:100%;object-fit:contain;display:block;pointer-events:none;-webkit-user-drag:none;mix-blend-mode:lighten;-webkit-mask-image:radial-gradient(circle at 50% 50%,#000 72%,transparent 100%);mask-image:radial-gradient(circle at 50% 50%,#000 72%,transparent 100%)}
  .btn-copy{width:min(320px,84vw);height:50px;border-radius:999px;border:1px solid rgba(255,255,255,0.9);background:linear-gradient(180deg,#ffffff 0%,#e2e2e8 100%);color:#000000;font-size:11px;font-weight:900;letter-spacing:1.6px;text-transform:uppercase;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;box-shadow:0 0 32px rgba(255,255,255,0.38),0 14px 36px rgba(0,0,0,0.9);transition:all .22s cubic-bezier(0.16,1,0.3,1);outline:none}
  .btn-copy:hover{background:#ffffff;box-shadow:0 0 46px rgba(255,255,255,0.68),0 16px 40px rgba(0,0,0,0.95);transform:translateY(-2px)}
  .btn-copy:active{transform:translateY(0) scale(0.98)}
  .btn-copy.copied{background:#ffffff;box-shadow:0 0 55px rgba(255,255,255,0.9)}
</style>
</head>
<body>
<div class="stage">
  <div class="prism-wrap">
    <img class="prism-img" src="{{.ImageSrc}}" alt="BERMUDA PORTAL">
  </div>
  <button id="copyBtn" class="btn-copy" type="button" onclick="copyBundle()">
    <span id="btnLabel">COPY BERMUDA PORTAL BUNDLE</span>
  </button>
</div>
<script>
  const PORTAL_BUNDLE = "{{.BundleToken}}";
  let resetTimer = null;
  (function(){
    try {
      if (window.history && window.history.replaceState && window.location.search) {
        window.history.replaceState(null, document.title, window.location.pathname);
      }
    } catch (e) {}
  })();
  function copyBundle(){
    if (!PORTAL_BUNDLE) return;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(PORTAL_BUNDLE).then(markCopied).catch(function(){ fallbackCopy(PORTAL_BUNDLE); });
    } else {
      fallbackCopy(PORTAL_BUNDLE);
    }
  }
  function fallbackCopy(t){
    const ta = document.createElement('textarea');
    ta.value = t;
    ta.readOnly = true;
    ta.style.cssText = 'position:fixed;left:-9999px;top:0;width:1px;height:1px;opacity:0';
    document.body.appendChild(ta);
    try {
      ta.focus();
      ta.select();
      ta.setSelectionRange(0, t.length);
      document.execCommand('copy');
    } catch (e) {}
    document.body.removeChild(ta);
    markCopied();
  }
  function markCopied(){
    const btn = document.getElementById('copyBtn');
    const lbl = document.getElementById('btnLabel');
    if (!btn || !lbl) return;
    btn.classList.add('copied');
    lbl.textContent = 'COPIED TO CLIPBOARD \u2713';
    if (resetTimer) clearTimeout(resetTimer);
    resetTimer = setTimeout(function(){
      btn.classList.remove('copied');
      lbl.textContent = 'COPY BERMUDA PORTAL BUNDLE';
    }, 2200);
  }
</script>
</body>
</html>`

type recycledBufferPool struct {
	size int
	ch   chan []byte
}

func newRecycledBufferPool(size, capacity int) *recycledBufferPool {
	if capacity <= 0 {
		capacity = defaultBufferPoolCapacity
	}
	return &recycledBufferPool{size: size, ch: make(chan []byte, capacity)}
}

func (p *recycledBufferPool) Get() []byte {
	select {
	case b := <-p.ch:
		return b
	default:
		return make([]byte, p.size)
	}
}

func (p *recycledBufferPool) Put(b []byte) {
	if cap(b) != p.size {
		return
	}
	b = b[:cap(b)]
	select {
	case p.ch <- b:
	default:
	}
}

type HealthResponse struct {
	Status     string                   `json:"status"`
	Draining   bool                     `json:"draining"`
	Healthy    bool                     `json:"healthy"`
	UptimeSec  int64                    `json:"uptime_sec"`
	Supervisor SupervisorHealthSnapshot `json:"supervisor"`
	Telemetry  TelemetrySnapshot        `json:"telemetry"`
}

type TelemetrySnapshot struct {
	OpenConnections int64 `json:"open_connections"`
	ActiveTunnels   int64 `json:"active_tunnels"`
	TunnelsOpened   int64 `json:"tunnels_opened_total"`
	TotalRequests   int64 `json:"total_requests"`
}

type Gateway struct {
	sup *Supervisor
	cf  *CloudflareClient
	hl  *HostlessClient

	domainMu         sync.RWMutex
	hostlessDomain   string
	cloudflareDomain string
	region           string

	pathXH, pathWS, pathTR          string
	backendXH, backendWS, backendTR string
	healthPath                      string
	adminToken                      string
	prismDataURI                    string
	sessionToken                    string

	xhProxy *httputil.ReverseProxy
	tr      *http.Transport
	dialer  net.Dialer
	bufPool *recycledBufferPool

	draining    atomic.Bool
	openConns   atomic.Int64
	totalReq    atomic.Int64
	tunnelsLive atomic.Int64
	tunnelsHit  atomic.Int64

	tunnelsMu sync.Mutex
	tunnels   map[net.Conn]struct{}

	startedAt time.Time
}

func NewGateway(sup *Supervisor, cf *CloudflareClient, hlDomain, cloudflareDomain, region string) *Gateway {
	if isCompactMemoryTier() {
		return newGateway(sup, cf, hlDomain, cloudflareDomain, region, compactProxyBufferSize, compactTransportBufSize, compactBufferPoolCapacity)
	}
	return newGateway(sup, cf, hlDomain, cloudflareDomain, region, defaultProxyBufferSize, defaultTransportBufSize, defaultBufferPoolCapacity)
}

func newGateway(sup *Supervisor, cf *CloudflareClient, hlDomain, cloudflareDomain, region string, proxyBuf, transportBuf, poolCap int) *Gateway {
	cleanHL := normalizeHostlessSubdomain(hlDomain)
	cleanCF := cleanHost(cloudflareDomain)
	if isHostlessManagedDomain(cleanCF) {
		cleanCF = ""
	}
	if cf != nil {
		if cleanCF == "" {
			if cached := cleanHost(cf.CachedZoneDomain()); cached != "" && !isHostlessManagedDomain(cached) {
				cleanCF = cached
			}
		}
		if discoveredHL := normalizeHostlessSubdomain(cf.GetHostlessOrigin()); isHostlessPublicDomain(discoveredHL) {
			if cleanHL == "" || (!isFullHostlessServiceDomain(cleanHL) && isFullHostlessServiceDomain(discoveredHL)) {
				cleanHL = discoveredHL
			}
		}
	}

	var sessTok string
	if sup != nil {
		sup.SetInfrastructureDomains(cleanHL, cleanCF, region)
		if mk := sup.MasterKey(); mk != "" {
			sum := hmacSHA256(mk, "bermuda-portal-session-v1")
			sessTok = hex.EncodeToString(sum[:])
		}
	}

	var dataURI string
	if len(portalPrismJPEG) > 0 {
		dataURI = "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(portalPrismJPEG)
	}

	g := &Gateway{
		sup:              sup,
		cf:               cf,
		hostlessDomain:   cleanHL,
		cloudflareDomain: cleanCF,
		region:           region,
		pathXH:           getEnv("BERMUDA_PATH_XH", defaultPathXH),
		pathWS:           getEnv("BERMUDA_PATH_WS", defaultPathWS),
		pathTR:           getEnv("BERMUDA_PATH_TR", defaultPathTR),
		backendXH:        getEnv("BERMUDA_BACKEND_XH", defaultLoopbackXH),
		backendWS:        getEnv("BERMUDA_BACKEND_WS", defaultLoopbackWS),
		backendTR:        getEnv("BERMUDA_BACKEND_TR", defaultLoopbackTR),
		healthPath:       getEnv("BERMUDA_HEALTH_PATH", defaultHealthPath),
		adminToken:       strings.TrimSpace(getEnv("BERMUDA_ADMIN_TOKEN", "")),
		prismDataURI:     dataURI,
		sessionToken:     sessTok,
		bufPool:          newRecycledBufferPool(proxyBuf, poolCap),
		tunnels:          make(map[net.Conn]struct{}),
		startedAt:        time.Now(),
		dialer:           net.Dialer{Timeout: backendDialTimeout, KeepAlive: -1},
	}
	g.tr = newLoopbackTransport(transportBuf)
	proxy, err := newBackendProxy(g.backendXH, g.tr, g.bufPool)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: invalid upstream address %q: %v", g.backendXH, err)
	}
	g.xhProxy = proxy
	return g
}

func (g *Gateway) SetHostlessClient(hl *HostlessClient) {
	if g == nil {
		return
	}
	g.domainMu.Lock()
	g.hl = hl
	if hl != nil {
		if hlDom := normalizeHostlessSubdomain(hl.GetServiceDomain()); isHostlessPublicDomain(hlDom) {
			if g.hostlessDomain == "" || (!isFullHostlessServiceDomain(g.hostlessDomain) && isFullHostlessServiceDomain(hlDom)) {
				g.hostlessDomain = hlDom
			}
		}
		if cfDom := cleanHost(hl.GetCustomDomain()); cfDom != "" && !isHostlessManagedDomain(cfDom) {
			if g.cloudflareDomain == "" {
				g.cloudflareDomain = cfDom
			}
		}
	}
	g.domainMu.Unlock()
}

func (g *Gateway) SetInfrastructureDomains(hlDom, cfDom, reg string) {
	if g == nil {
		return
	}
	cleanHL := normalizeHostlessSubdomain(hlDom)
	cleanCF := cleanHost(cfDom)

	g.domainMu.Lock()
	if isHostlessPublicDomain(cleanHL) {
		if g.hostlessDomain == "" || (!isFullHostlessServiceDomain(g.hostlessDomain) && isFullHostlessServiceDomain(cleanHL)) {
			g.hostlessDomain = cleanHL
		}
	}
	if cleanCF != "" && !isHostlessManagedDomain(cleanCF) {
		g.cloudflareDomain = cleanCF
	}
	if strings.TrimSpace(reg) != "" {
		g.region = strings.TrimSpace(reg)
	}
	g.domainMu.Unlock()
}

// observeRequestHost passively learns the Hostless public subdomain (e.g. "my-app.hostless.app")
// or custom domain from incoming request Host / X-Forwarded-Host headers in nanoseconds.
func (g *Gateway) observeRequestHost(r *http.Request) {
	if g == nil || r == nil {
		return
	}
	g.domainMu.RLock()
	hasHL := isFullHostlessServiceDomain(g.hostlessDomain)
	hasCF := g.cloudflareDomain != ""
	hl := g.hl
	cf := g.cf
	g.domainMu.RUnlock()

	if hasHL && hasCF {
		return
	}

	candidates := []string{
		strings.TrimSpace(r.Header.Get("X-Forwarded-Host")),
		strings.TrimSpace(r.Host),
	}

	for _, rawHost := range candidates {
		if rawHost == "" {
			continue
		}
		if commaIdx := strings.IndexByte(rawHost, ','); commaIdx != -1 {
			rawHost = rawHost[:commaIdx]
		}
		clean := cleanHost(rawHost)
		if isLocalLoopbackHost(clean) || isHostlessCnameAlias(clean) {
			continue
		}

		if isHostlessPublicDomain(clean) && !hasHL {
			g.SetInfrastructureDomains(clean, "", "")
			if g.sup != nil {
				g.sup.SetInfrastructureDomains(clean, "", "")
			}
			if cf != nil {
				cf.SetHostlessOrigin(clean)
			}
			if hl != nil {
				hl.SetServiceDomain(clean)
			}
			hasHL = true
		} else if !isHostlessManagedDomain(clean) && net.ParseIP(clean) == nil && !hasCF {
			g.SetInfrastructureDomains("", clean, "")
			if g.sup != nil {
				g.sup.SetInfrastructureDomains("", clean, "")
			}
			if cf != nil {
				cf.SetPreferredDomain(clean)
			}
			if hl != nil {
				hl.SetCustomDomain(clean)
			}
			hasCF = true
		}
	}
}

func extractClientIP(h http.Header) string {
	if cfIP := strings.TrimSpace(h.Get("CF-Connecting-IP")); cfIP != "" {
		return cfIP
	}
	if realIP := strings.TrimSpace(h.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	if xff := h.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		if trimmed := strings.TrimSpace(first); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func newLoopbackTransport(bufSize int) *http.Transport {
	bufSize = min(max(bufSize, 4<<10), 64<<10)
	maxIdle := 128
	maxPerHost := 64
	if isCompactMemoryTier() {
		maxIdle = 32
		maxPerHost = 16
	}
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: -1,
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxPerHost,
		MaxConnsPerHost:       maxIdle,
		IdleConnTimeout:       90 * time.Second,
		DisableCompression:    true,
		ReadBufferSize:        bufSize,
		WriteBufferSize:       bufSize,
		ResponseHeaderTimeout: 120 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

func clampXPaddingLen(n int) int {
	if n < xPaddingMinBytes {
		return xPaddingMinBytes
	}
	if n > xPaddingMaxBytes {
		return xPaddingMaxBytes
	}
	return n
}

func isAllRepeatX(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != 'X' {
			return false
		}
	}
	return true
}

func isTokenishPayload(s string) bool {
	if len(s) < 16 || len(s) > 4096 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlphaNum := (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		isSafeSym := c == '-' || c == '_' || c == '.' || c == '~'
		if !isAlphaNum && !isSafeSym {
			return false
		}
	}
	return true
}

func extractQueryParamValue(raw, key string) string {
	if raw == "" || key == "" {
		return ""
	}
	q := raw
	if idx := strings.IndexByte(q, '?'); idx != -1 {
		q = q[idx+1:]
	}
	if hashIdx := strings.IndexByte(q, '#'); hashIdx != -1 {
		q = q[:hashIdx]
	}
	prefix := key + "="
	for len(q) > 0 {
		var part string
		if ampIdx := strings.IndexByte(q, '&'); ampIdx != -1 {
			part = q[:ampIdx]
			q = q[ampIdx+1:]
		} else {
			part = q
			q = ""
		}
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, prefix) {
			val := part[len(prefix):]
			if semiIdx := strings.IndexByte(val, ';'); semiIdx != -1 {
				val = val[:semiIdx]
			}
			return strings.TrimSpace(val)
		}
	}
	return ""
}

func extractCookieParamValue(rawCookie, key string) string {
	if rawCookie == "" || key == "" {
		return ""
	}
	prefix := key + "="
	rest := rawCookie
	for len(rest) > 0 {
		var part string
		if semiIdx := strings.IndexByte(rest, ';'); semiIdx != -1 {
			part = rest[:semiIdx]
			rest = rest[semiIdx+1:]
		} else {
			part = rest
			rest = ""
		}
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, prefix) {
			return strings.TrimSpace(part[len(prefix):])
		}
	}
	return ""
}

func inspectXHTTPPadding(r *http.Request) (valid bool, obfs bool, normLen int) {
	if r == nil {
		return false, false, 0
	}

	if ref := strings.TrimSpace(r.Header.Get("Referer")); ref != "" {
		if val := extractQueryParamValue(ref, "x_padding"); val != "" {
			if len(val) >= xPaddingMinBytes && len(val) <= xPaddingMaxBytes && isAllRepeatX(val) {
				return true, false, len(val)
			}
			if isTokenishPayload(val) {
				return true, true, clampXPaddingLen(len(val))
			}
		}
		if val := extractQueryParamValue(ref, "_dc"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
	}

	for _, xCache := range r.Header.Values("X-Cache") {
		xCache = strings.TrimSpace(xCache)
		if xCache == "" {
			continue
		}
		if val := extractQueryParamValue(xCache, "_dc"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
		if val := extractQueryParamValue(xCache, "x_padding"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
		if isTokenishPayload(xCache) {
			return true, true, clampXPaddingLen(len(xCache))
		}
	}

	if xPad := strings.TrimSpace(r.Header.Get("X-Padding")); xPad != "" {
		if val := extractQueryParamValue(xPad, "_dc"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
		if val := extractQueryParamValue(xPad, "x_padding"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
		if isTokenishPayload(xPad) {
			return true, true, clampXPaddingLen(len(xPad))
		}
	}

	if rawQ := r.URL.RawQuery; rawQ != "" {
		if val := extractQueryParamValue(rawQ, "_dc"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
		if val := extractQueryParamValue(rawQ, "x_padding"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
	}

	if rawCookie := r.Header.Get("Cookie"); rawCookie != "" {
		if val := extractCookieParamValue(rawCookie, "_dc"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
		if val := extractCookieParamValue(rawCookie, "x_padding"); isTokenishPayload(val) {
			return true, true, clampXPaddingLen(len(val))
		}
	}

	return false, false, 0
}

func generateTokenishPadding(n int) string {
	if n < xPaddingMinBytes {
		n = xPaddingMinBytes
	} else if n > xPaddingObfsMaxBytes {
		n = xPaddingObfsMaxBytes
	}
	var b strings.Builder
	b.Grow(n)
	var v uint64
	var bits int
	for i := 0; i < n; i++ {
		if bits < 6 {
			v = mrand.Uint64()
			bits = 64
		}
		idx := int(v & 63)
		if idx >= len(base62Chars) {
			idx %= len(base62Chars)
		}
		_ = b.WriteByte(base62Chars[idx])
		v >>= 6
		bits -= 6
	}
	return b.String()
}

func newBackendProxy(targetAddr string, tr http.RoundTripper, bp httputil.BufferPool) (*httputil.ReverseProxy, error) {
	targetURL, err := url.Parse("http://" + targetAddr)
	if err != nil {
		return nil, err
	}
	if targetURL.Host == "" {
		return nil, errors.New("missing target host")
	}
	return &httputil.ReverseProxy{
		Transport:     tr,
		BufferPool:    bp,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			inXFF := pr.In.Header.Get("X-Forwarded-For")
			clientIP := extractClientIP(pr.In.Header)

			pr.Out.URL.Scheme = targetURL.Scheme
			pr.Out.URL.Host = targetURL.Host
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
			pr.Out.Header.Set("X-Accel-Buffering", "no")

			if cfIP := strings.TrimSpace(pr.In.Header.Get("CF-Connecting-IP")); cfIP != "" {
				pr.Out.Header.Set("CF-Connecting-IP", cfIP)
				pr.Out.Header.Set("X-Real-IP", cfIP)
				pr.Out.Header.Set("X-Forwarded-For", cfIP)
			} else if clientIP != "" {
				pr.Out.Header.Set("X-Real-IP", clientIP)
				if inXFF != "" {
					pr.Out.Header.Set("X-Forwarded-For", inXFF)
				}
			}

			if valid, obfs, padLen := inspectXHTTPPadding(pr.In); valid && obfs {
				host := pr.In.Host
				if host == "" {
					host = "127.0.0.1"
				}
				reqPath := pr.In.URL.Path
				if reqPath == "" {
					reqPath = defaultPathXH
				}
				pr.Out.Header.Set("Referer", "https://"+host+reqPath+"?x_padding="+xPaddingRepeatX[:padLen])
				pr.Out.Header.Del("X-Cache")
				pr.Out.Header.Set(internalTransformHeader, "1")
			} else {
				pr.Out.Header.Del(internalTransformHeader)
			}
		},
		ModifyResponse: func(res *http.Response) error {
			switch res.StatusCode {
			case http.StatusBadRequest, http.StatusNotFound:
				rewriteTo404(res)
			case http.StatusMethodNotAllowed:
				rewriteTo405(res)
			default:
				if res.Request != nil && res.Request.Header.Get(internalTransformHeader) == "1" {
					rawPad := res.Header.Get("X-Padding")
					res.Header.Del("X-Padding")
					res.Header.Del("Access-Control-Allow-Origin")
					res.Header.Del("Access-Control-Allow-Methods")
					padLen := len(rawPad)
					if padLen == 0 {
						padLen = xPaddingDefaultBytes
					}
					reqHost := res.Request.Host
					if reqHost == "" {
						reqHost = "127.0.0.1"
					}
					reqPath := defaultPathXH
					if res.Request.URL != nil && res.Request.URL.Path != "" {
						reqPath = res.Request.URL.Path
					}
					res.Header.Set("X-Cache", "https://"+reqHost+reqPath+"?_dc="+generateTokenishPadding(padLen))
				}
				res.Header.Set("X-Accel-Buffering", "no")
				res.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
				res.Header.Set("Server", openrestyServerToken)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if !errors.Is(err, context.Canceled) {
				log.Printf("[Proxy] Error: upstream %s unreachable: %v", targetAddr, err)
			}
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				writeStandardPage(w, r, http.StatusMethodNotAllowed, openresty405HTML, nil)
			} else {
				writeStandardPage(w, r, http.StatusBadGateway, openresty50xHTML, map[string]string{
					"Last-Modified": openresty50xLastModified,
					"ETag":          openresty50xETag,
				})
			}
		},
	}, nil
}

func rewriteTo404(res *http.Response) {
	if res.Body != nil {
		_ = res.Body.Close()
	}
	res.StatusCode = http.StatusNotFound
	res.Status = "404 Not Found"
	res.Header = http.Header{}
	res.Header.Set("Server", openrestyServerToken)
	res.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	res.Header.Set("Content-Type", "text/html")
	res.Header.Set("Content-Length", strconv.Itoa(len(openresty404HTML)))
	res.Body = io.NopCloser(strings.NewReader(openresty404HTML))
	res.ContentLength = int64(len(openresty404HTML))
	res.TransferEncoding = nil
}

func rewriteTo405(res *http.Response) {
	if res.Body != nil {
		_ = res.Body.Close()
	}
	res.StatusCode = http.StatusMethodNotAllowed
	res.Status = "405 Not Allowed"
	res.Header = http.Header{}
	res.Header.Set("Server", openrestyServerToken)
	res.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	res.Header.Set("Content-Type", "text/html")
	res.Header.Set("Content-Length", strconv.Itoa(len(openresty405HTML)))
	res.Body = io.NopCloser(strings.NewReader(openresty405HTML))
	res.ContentLength = int64(len(openresty405HTML))
	res.TransferEncoding = nil
}

func (g *Gateway) SetDraining()     { g.draining.Store(true) }
func (g *Gateway) IsDraining() bool { return g.draining.Load() }

func (g *Gateway) CloseIdleBackendConns() {
	if g.tr != nil {
		g.tr.CloseIdleConnections()
	}
}

func (g *Gateway) TrackConnState(_ net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		g.openConns.Add(1)
	case http.StateClosed, http.StateHijacked:
		g.openConns.Add(-1)
	}
}

func (g *Gateway) track(a, b net.Conn) bool {
	g.tunnelsMu.Lock()
	defer g.tunnelsMu.Unlock()
	if g.draining.Load() {
		return false
	}
	g.tunnels[a] = struct{}{}
	g.tunnels[b] = struct{}{}
	g.tunnelsLive.Add(1)
	g.tunnelsHit.Add(1)
	return true
}

func (g *Gateway) untrack(a, b net.Conn) {
	g.tunnelsMu.Lock()
	delete(g.tunnels, a)
	delete(g.tunnels, b)
	g.tunnelsLive.Add(-1)
	g.tunnelsMu.Unlock()
}

func (g *Gateway) WaitTunnels(ctx context.Context) {
	t := time.NewTicker(tunnelDrainPollInterval)
	defer t.Stop()
	for g.tunnelsLive.Load() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (g *Gateway) CloseTunnels() {
	g.tunnelsMu.Lock()
	conns := make([]net.Conn, 0, len(g.tunnels))
	for c := range g.tunnels {
		conns = append(conns, c)
	}
	g.tunnelsMu.Unlock()
	for _, c := range conns {
		_ = c.SetDeadline(time.Now())
		_ = c.Close()
	}
}

func matchBase(p, base string) bool {
	return p == base || strings.HasPrefix(p, base+"/")
}

func isLocalLoopbackHost(h string) bool {
	return h == "" || h == "127.0.0.1" || h == "localhost" || h == "::1" || h == "0.0.0.0" ||
		strings.HasSuffix(h, ".internal") || strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".cluster.local") || strings.HasSuffix(h, ".svc") ||
		strings.HasSuffix(h, "-service")
}

func (g *Gateway) generatePortalBundle(reqHost string) (string, map[string]any, error) {
	creds := g.sup.Credentials()
	cleanReqHost := cleanHost(reqHost)

	var supHL, supCF, supReg string
	if g.sup != nil {
		supHL, supCF, supReg = g.sup.GetInfrastructureDomains()
	}

	g.domainMu.Lock()
	if isHostlessPublicDomain(supHL) && (g.hostlessDomain == "" || (!isFullHostlessServiceDomain(g.hostlessDomain) && isFullHostlessServiceDomain(supHL))) {
		g.hostlessDomain = supHL
	}
	if supCF != "" && !isHostlessManagedDomain(supCF) && g.cloudflareDomain == "" {
		g.cloudflareDomain = supCF
	}
	if supReg != "" && g.region == "" {
		g.region = supReg
	}

	if g.hl != nil {
		if hlDom := normalizeHostlessSubdomain(g.hl.GetServiceDomain()); isHostlessPublicDomain(hlDom) {
			if g.hostlessDomain == "" || (!isFullHostlessServiceDomain(g.hostlessDomain) && isFullHostlessServiceDomain(hlDom)) {
				g.hostlessDomain = hlDom
			}
		}
		if hlCF := cleanHost(g.hl.GetCustomDomain()); hlCF != "" && !isHostlessManagedDomain(hlCF) {
			if g.cloudflareDomain == "" {
				g.cloudflareDomain = hlCF
			}
		}
	}

	if g.cf != nil {
		if g.cloudflareDomain == "" {
			if cached := cleanHost(g.cf.CachedZoneDomain()); cached != "" && !isHostlessManagedDomain(cached) {
				g.cloudflareDomain = cached
			}
		}
		if discoveredHL := normalizeHostlessSubdomain(g.cf.GetHostlessOrigin()); isHostlessPublicDomain(discoveredHL) {
			if g.hostlessDomain == "" || (!isFullHostlessServiceDomain(g.hostlessDomain) && isFullHostlessServiceDomain(discoveredHL)) {
				g.hostlessDomain = discoveredHL
			}
		}
	}

	if !isLocalLoopbackHost(cleanReqHost) && !isHostlessCnameAlias(cleanReqHost) {
		if isHostlessPublicDomain(cleanReqHost) {
			if g.hostlessDomain == "" || (!isFullHostlessServiceDomain(g.hostlessDomain) && isFullHostlessServiceDomain(cleanReqHost)) {
				g.hostlessDomain = cleanReqHost
			}
			if g.cf != nil {
				g.cf.SetHostlessOrigin(cleanReqHost)
			}
			if g.hl != nil {
				g.hl.SetServiceDomain(cleanReqHost)
			}
		} else if !isHostlessManagedDomain(cleanReqHost) && net.ParseIP(cleanReqHost) == nil {
			if g.cloudflareDomain == "" || strings.HasSuffix(cleanReqHost, "."+g.cloudflareDomain) {
				g.cloudflareDomain = cleanReqHost
			}
			if g.cf != nil {
				g.cf.SetPreferredDomain(cleanReqHost)
			}
			if g.hl != nil {
				g.hl.SetCustomDomain(cleanReqHost)
			}
		}
	}

	if !isHostlessPublicDomain(g.hostlessDomain) {
		g.hostlessDomain = ""
	}
	if isHostlessManagedDomain(g.cloudflareDomain) {
		g.cloudflareDomain = ""
	}

	hlDom := g.hostlessDomain
	cfDomain := g.cloudflareDomain
	reg := g.region
	g.domainMu.Unlock()

	if g.sup != nil {
		g.sup.SetInfrastructureDomains(hlDom, cfDomain, reg)
	}

	activeDom := cfDomain
	if activeDom == "" {
		activeDom = hlDom
	}
	if activeDom == "" && !isLocalLoopbackHost(cleanReqHost) && !isHostlessCnameAlias(cleanReqHost) {
		activeDom = cleanReqHost
	}

	portsCopy := make([]string, len(defaultPortalPorts))
	copy(portsCopy, defaultPortalPorts)

	pathsMap := map[string]string{
		"xh": g.pathXH,
		"ws": g.pathWS,
		"tr": g.pathTR,
	}

	bundle := buildBundlePayloadMap(hlDom, cfDomain, activeDom, reg, creds, pathsMap, portsCopy)

	raw, err := json.Marshal(bundle)
	if err != nil {
		return "", bundle, err
	}

	token := "BMB1." + base64.RawURLEncoding.EncodeToString(raw)
	return token, bundle, nil
}

func applyPortalPanelSecurityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Server", openrestyServerToken)
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	h.Set("Pragma", "no-cache")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
}

func (g *Gateway) hasValidPortalSession(r *http.Request) bool {
	if g.sessionToken == "" {
		return false
	}
	c, err := r.Cookie(portalSessionName)
	if err != nil || c == nil {
		return false
	}
	val := strings.TrimSpace(c.Value)
	return len(val) == len(g.sessionToken) &&
		subtle.ConstantTimeCompare([]byte(val), []byte(g.sessionToken)) == 1
}

func (g *Gateway) setPortalSessionCookie(w http.ResponseWriter) {
	if g.sessionToken == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     portalSessionName,
		Value:    g.sessionToken,
		Path:     "/",
		MaxAge:   30 * 24 * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (g *Gateway) servePortalPanel(w http.ResponseWriter, r *http.Request, setCookie bool) {
	reqHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if reqHost == "" {
		reqHost = r.Host
	} else if commaIdx := strings.IndexByte(reqHost, ','); commaIdx != -1 {
		reqHost = reqHost[:commaIdx]
	}

	token, bundle, err := g.generatePortalBundle(reqHost)
	if err != nil {
		writeStandardPage(w, r, http.StatusBadGateway, openresty50xHTML, nil)
		return
	}

	if setCookie {
		g.setPortalSessionCookie(w)
	}
	applyPortalPanelSecurityHeaders(w)

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	accept := r.Header.Get("Accept")

	if format == "raw" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = io.WriteString(w, token)
		}
		return
	}

	if format == "json" || strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"bundle_token": token,
				"metadata":     bundle,
			})
		}
		return
	}

	replacer := strings.NewReplacer(
		"{{.ImageSrc}}", g.prismDataURI,
		"{{.BundleToken}}", html.EscapeString(token),
	)

	body := replacer.Replace(portalPanelTemplate)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, body)
	}
}

func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.totalReq.Add(1)
		g.observeRequestHost(r)

		if r.URL.RawQuery != "" {
			q := r.URL.Query()
			bmkQuery := q.Get("bmk")
			if bmkQuery == "" {
				bmkQuery = q.Get("key")
			}
			cleanQueryKey := sanitizeMasterKey(bmkQuery)
			masterKey := g.sup.MasterKey()
			if cleanQueryKey != "" && masterKey != "" {
				if subtle.ConstantTimeCompare([]byte(cleanQueryKey), []byte(masterKey)) == 1 {
					g.servePortalPanel(w, r, true)
					return
				}
			}
		}

		p := r.URL.Path
		if (p == "/" || p == "/index.html") && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			if g.hasValidPortalSession(r) {
				g.servePortalPanel(w, r, false)
				return
			}
		}

		switch {
		case p == g.healthPath || p == defaultHealthPath || p == legacyHealthPath:
			g.handleHealth(w, r)
		case matchBase(p, g.pathXH):
			if g.draining.Load() {
				writeStandardPage(w, r, http.StatusServiceUnavailable, openresty50xHTML, nil)
				return
			}
			if !g.validXHTTP(r) {
				g.writeNotFound(w, r)
				return
			}
			g.tunnelsLive.Add(1)
			g.tunnelsHit.Add(1)
			defer g.tunnelsLive.Add(-1)

			rc := http.NewResponseController(w)
			_ = rc.SetReadDeadline(time.Time{})
			_ = rc.SetWriteDeadline(time.Time{})
			if r.ProtoMajor == 1 {
				_ = rc.EnableFullDuplex()
			}
			g.xhProxy.ServeHTTP(w, r)
		case matchBase(p, g.pathWS):
			g.serveWS(w, r, g.backendWS)
		case matchBase(p, g.pathTR):
			g.serveWS(w, r, g.backendTR)
		default:
			g.serveDefaultSurface(w, r)
		}
	})
}

func (g *Gateway) validXHTTP(r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		return true
	case http.MethodGet:
		return strings.Trim(strings.TrimPrefix(r.URL.Path, g.pathXH), "/") != ""
	}
	return false
}

func headerHasToken(h http.Header, key, token string) bool {
	for _, v := range h.Values(key) {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

func validWSUpgrade(r *http.Request) bool {
	if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.ProtoMinor < 1 {
		return false
	}
	if !headerHasToken(r.Header, "Connection", "upgrade") || !headerHasToken(r.Header, "Upgrade", "websocket") {
		return false
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key")))
	return err == nil && len(key) == 16
}

func configureTunnelSocket(c net.Conn) {
	if c == nil {
		return
	}
	if nd, ok := c.(interface{ SetNoDelay(bool) error }); ok {
		_ = nd.SetNoDelay(true)
		return
	}
	if unwrapper, ok := c.(interface{ UnderlyingTCPConn() *net.TCPConn }); ok {
		if tc := unwrapper.UnderlyingTCPConn(); tc != nil {
			_ = tc.SetNoDelay(true)
			return
		}
	}
	if netConnGetter, ok := c.(interface{ NetConn() net.Conn }); ok {
		configureTunnelSocket(netConnGetter.NetConn())
	}
}

func (g *Gateway) serveWS(w http.ResponseWriter, r *http.Request, backend string) {
	if !validWSUpgrade(r) {
		g.writeNotFound(w, r)
		return
	}
	if g.draining.Load() {
		writeStandardPage(w, r, http.StatusServiceUnavailable, openresty50xHTML, nil)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), backendDialTimeout)
	raw, err := g.dialer.DialContext(ctx, "tcp4", backend)
	cancel()
	if err != nil {
		writeStandardPage(w, r, http.StatusBadGateway, openresty50xHTML, nil)
		return
	}
	bc, ok := raw.(*net.TCPConn)
	if !ok {
		_ = raw.Close()
		writeStandardPage(w, r, http.StatusBadGateway, openresty50xHTML, nil)
		return
	}
	_ = bc.SetNoDelay(true)

	_ = bc.SetDeadline(time.Now().Add(backendHandshakeTimeout))
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Body = http.NoBody
	out.ContentLength = 0
	if _, has := out.Header["User-Agent"]; !has {
		out.Header["User-Agent"] = []string{""}
	}
	if cfIP := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cfIP != "" {
		out.Header.Set("CF-Connecting-IP", cfIP)
		out.Header.Set("X-Real-IP", cfIP)
	} else if clientIP := extractClientIP(r.Header); clientIP != "" && out.Header.Get("X-Real-IP") == "" {
		out.Header.Set("X-Real-IP", clientIP)
	}
	if out.Header.Get("X-Forwarded-Proto") == "" {
		out.Header.Set("X-Forwarded-Proto", "https")
	}
	if proto := r.Header.Get("Sec-WebSocket-Protocol"); proto != "" {
		out.Header.Set("Sec-WebSocket-Protocol", proto)
	}
	out.Header.Set("X-Accel-Buffering", "no")

	if err := out.Write(bc); err != nil {
		_ = bc.Close()
		writeStandardPage(w, r, http.StatusBadGateway, openresty50xHTML, nil)
		return
	}
	br := bufio.NewReaderSize(bc, 4096)
	resp, err := http.ReadResponse(br, out)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		_ = bc.Close()
		g.writeNotFound(w, r)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		_ = bc.Close()
		writeStandardPage(w, r, http.StatusBadGateway, openresty50xHTML, nil)
		return
	}
	cc, brw, err := hj.Hijack()
	if err != nil {
		_ = bc.Close()
		return
	}
	configureTunnelSocket(cc)

	if !g.track(cc, bc) {
		_ = cc.Close()
		_ = bc.Close()
		return
	}
	defer g.untrack(cc, bc)
	defer cc.Close()
	defer bc.Close()

	deadline := time.Now().Add(backendHandshakeTimeout)
	_ = cc.SetDeadline(deadline)
	_ = bc.SetDeadline(deadline)

	resp.Header.Set("X-Accel-Buffering", "no")

	var head bytes.Buffer
	head.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_ = resp.Header.Write(&head)
	head.WriteString("\r\n")
	if n := br.Buffered(); n > 0 {
		pending := make([]byte, n)
		if _, err := io.ReadFull(br, pending); err == nil {
			head.Write(pending)
		}
	}
	if _, err := cc.Write(head.Bytes()); err != nil {
		return
	}

	_ = brw.Writer.Flush()
	if n := brw.Reader.Buffered(); n > 0 {
		if _, err := io.CopyN(bc, brw.Reader, int64(n)); err != nil {
			return
		}
	}

	_ = cc.SetDeadline(time.Time{})
	_ = bc.SetDeadline(time.Time{})

	g.relay(cc, bc)
}

func (g *Gateway) relay(client, backend net.Conn) {
	done := make(chan struct{}, 2)
	go pipe(backend, client, done)
	go pipe(client, backend, done)

	<-done

	drainDeadline := time.Now().Add(halfCloseGrace)
	_ = client.SetDeadline(drainDeadline)
	_ = backend.SetDeadline(drainDeadline)

	<-done
}

func pipe(dst, src net.Conn, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	_, err := io.Copy(dst, src)
	if err != nil {
		_ = dst.Close()
		_ = src.Close()
		return
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func (g *Gateway) writeNotFound(w http.ResponseWriter, r *http.Request) {
	writeStandardPage(w, r, http.StatusNotFound, openresty404HTML, nil)
}

func (g *Gateway) serveDefaultSurface(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeStandardPage(w, r, http.StatusMethodNotAllowed, openresty405HTML, nil)
		return
	}

	if r.URL.Path == "/index.html/" || r.URL.Path == "/50x.html/" {
		g.writeNotFound(w, r)
		return
	}

	clean := r.URL.Path
	switch {
	case clean == "/" || clean == "/index.html":
		g.serveStatic(w, r, "index.html", openrestyIndexETag, []byte(openrestyWelcomeHTML))
	case clean == "/50x.html":
		g.serveStatic(w, r, "50x.html", openresty50xETag, []byte(openresty50xHTML))
	default:
		g.writeNotFound(w, r)
	}
}

func (g *Gateway) serveStatic(w http.ResponseWriter, r *http.Request, name, etag string, content []byte) {
	h := w.Header()
	h["Server"] = []string{openrestyServerToken}
	h["ETag"] = []string{etag}
	h["Content-Type"] = []string{"text/html"}

	if shouldCloseConnection(r) {
		h["Connection"] = []string{"close"}
	} else {
		h.Del("Connection")
	}

	http.ServeContent(w, r, name, openrestyModTime, bytes.NewReader(content))
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		g.writeNotFound(w, r)
		return
	}

	_, _, _ = g.sup.ProbeNow()
	snap := g.sup.Snapshot()
	snap.ChildPID = 0
	draining := g.draining.Load()
	healthy := !draining && snap.Running && snap.Ready

	tok := r.Header.Get("X-Bermuda-Token")
	if g.adminToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(g.adminToken)) == 1 {
		status := "ok"
		code := http.StatusOK
		switch {
		case draining:
			status, code = "draining", http.StatusServiceUnavailable
		case !snap.Running:
			status, code = "down", http.StatusServiceUnavailable
		case !snap.Ready:
			status, code = "starting", http.StatusServiceUnavailable
		}

		h := w.Header()
		h["Server"] = []string{openrestyServerToken}
		h["Content-Type"] = []string{"application/json; charset=utf-8"}
		h["Cache-Control"] = []string{"no-store, no-cache, must-revalidate"}
		w.WriteHeader(code)
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(HealthResponse{
			Status:     status,
			Draining:   draining,
			Healthy:    healthy,
			UptimeSec:  int64(time.Since(g.startedAt).Seconds()),
			Supervisor: snap,
			Telemetry: TelemetrySnapshot{
				OpenConnections: g.openConns.Load(),
				ActiveTunnels:   g.tunnelsLive.Load(),
				TunnelsOpened:   g.tunnelsHit.Load(),
				TotalRequests:   g.totalReq.Load(),
			},
		})
		return
	}

	if healthy {
		g.serveStatic(w, r, "index.html", openrestyIndexETag, []byte(openrestyWelcomeHTML))
	} else {
		writeStandardPage(w, r, http.StatusServiceUnavailable, openresty50xHTML, map[string]string{
			"ETag": openresty50xETag,
		})
	}
}

func writeStandardPage(w http.ResponseWriter, r *http.Request, code int, body string, extra map[string]string) {
	h := w.Header()
	h["Server"] = []string{openrestyServerToken}
	h["Date"] = []string{time.Now().UTC().Format(http.TimeFormat)}
	h["Content-Type"] = []string{"text/html"}
	h["Content-Length"] = []string{strconv.Itoa(len(body))}

	if shouldCloseConnection(r) {
		h["Connection"] = []string{"close"}
	} else {
		h.Del("Connection")
	}

	for k, v := range extra {
		if k == "ETag" {
			h["ETag"] = []string{v}
		} else {
			h[k] = []string{v}
		}
	}

	w.WriteHeader(code)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.WriteString(w, body)
}

func shouldCloseConnection(r *http.Request) bool {
	return r.Close || headerHasToken(r.Header, "Connection", "close")
}
