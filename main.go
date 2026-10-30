package main

import (
	"context"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultPort               = "8080"
	compatAltPort             = "3000"
	compactSelfMemMB          = 40
	compactWorkerMemMB        = 136
	standardSelfMemMB         = 122
	standardWorkerMemMB       = 550
	defaultGOMAXPROCS         = 2
	gatewayMemPercent         = 12
	workerMemPercent          = 54
	compactTierThresholdMB    = 384
	httpDrainTimeout          = 8 * time.Second
	edgeKeepAlivePeriod       = 15 * time.Second
	drainPropagationWindow    = 400 * time.Millisecond
	startupOrchestrationDelay = 3 * time.Second
	dnsPropagationSettleDelay = 4 * time.Second
	tcpUserTimeoutOpt         = 18
)

var compactMemoryMode atomic.Bool

func isCompactMemoryTier() bool {
	return compactMemoryMode.Load()
}

func cgroupMemoryLimit() (uint64, bool) {
	candidates := []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(data))
		if s == "" || s == "max" {
			continue
		}
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil || n == 0 || n >= 1<<50 {
			continue
		}
		return n, true
	}

	for _, envKey := range []string{"MEMORY_LIMIT", "BERMUDA_CONTAINER_MEM_MB"} {
		if raw := strings.TrimSpace(getEnv(envKey, "")); raw != "" {
			if mb, err := strconv.ParseUint(raw, 10, 64); err == nil && mb >= 64 && mb <= 65536 {
				return mb << 20, true
			}
		}
	}

	return 0, false
}

func deriveMemoryBudget() (gwMB, workerMB int, compact bool) {
	// Default calibrated for Hostless Cloud's 1 GiB (1024 MiB) Free Tier entitlement,
	// with automatic Compact Mode fallback if the container cgroup is <= 384 MiB.
	gwMB, workerMB, compact = standardSelfMemMB, standardWorkerMemMB, false

	limit, limited := cgroupMemoryLimit()
	if limited {
		totalMB := int(limit >> 20)
		if totalMB > compactTierThresholdMB {
			compact = false
			gwMB = totalMB * gatewayMemPercent / 100
			workerMB = totalMB * workerMemPercent / 100

			allowedMB := totalMB * 66 / 100
			if gwMB < 48 {
				gwMB = 48
			}
			if workerMB < 128 {
				workerMB = 128
			}
			if total := gwMB + workerMB; total > allowedMB && allowedMB >= 176 {
				gwMB = allowedMB * gatewayMemPercent / 66
				workerMB = allowedMB * workerMemPercent / 66
			}
		} else {
			compact = true
			gwMB = totalMB * 15 / 100
			workerMB = totalMB * 52 / 100
			if gwMB < 32 {
				gwMB = 32
			}
			if gwMB > 44 {
				gwMB = 44
			}
			if workerMB < 96 {
				workerMB = 96
			}
			if workerMB > 140 {
				workerMB = 140
			}
		}
	}

	if explicitLow := strings.ToLower(strings.TrimSpace(getEnv("BERMUDA_LOW_MEM", ""))); explicitLow == "true" || explicitLow == "1" {
		compact = true
		if gwMB > compactSelfMemMB {
			gwMB = compactSelfMemMB
		}
		if workerMB > compactWorkerMemMB {
			workerMB = compactWorkerMemMB
		}
	} else if explicitLow == "false" || explicitLow == "0" {
		compact = false
		if !limited {
			gwMB, workerMB = standardSelfMemMB, standardWorkerMemMB
		}
	}

	gwMB = getEnvInt("BERMUDA_SELF_MEM_MB", gwMB)
	workerMB = getEnvInt("BERMUDA_WORKER_MEM_MB", getEnvInt("BERMUDA_XRAY_MEM_MB", workerMB))
	compactMemoryMode.Store(compact)
	return gwMB, workerMB, compact
}

func applyMemoryCeiling(selfMB int, compact bool) {
	if selfMB < 32 {
		selfMB = 32
	}
	debug.SetMemoryLimit(int64(selfMB) << 20)
	if compact {
		debug.SetGCPercent(50)
	} else {
		debug.SetGCPercent(100)
	}
}

func cgroupCPUQuota() (float64, bool) {
	if data, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		f := strings.Fields(string(data))
		if len(f) == 2 && f[0] != "max" {
			q, e1 := strconv.ParseFloat(f[0], 64)
			p, e2 := strconv.ParseFloat(f[1], 64)
			if e1 == nil && e2 == nil && q > 0 && p > 0 {
				return q / p, true
			}
		}
	}
	qb, e1 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")
	pb, e2 := os.ReadFile("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
	if e1 == nil && e2 == nil {
		q, e3 := strconv.ParseFloat(strings.TrimSpace(string(qb)), 64)
		p, e4 := strconv.ParseFloat(strings.TrimSpace(string(pb)), 64)
		if e3 == nil && e4 == nil && q > 0 && p > 0 {
			return q / p, true
		}
	}
	return 0, false
}

func applyGOMAXPROCS() int {
	n := getEnvInt("BERMUDA_GOMAXPROCS", 0)
	if n == 0 {
		if q, ok := cgroupCPUQuota(); ok {
			n = int(math.Ceil(q))
		}
	}
	if n < 2 {
		n = defaultGOMAXPROCS
	}
	if cpus := runtime.NumCPU(); n > cpus && cpus > 0 {
		n = cpus
	}
	runtime.GOMAXPROCS(n)
	return n
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func cleanHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "${{") || strings.HasPrefix(h, "$") {
		return ""
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	if slashIdx := strings.IndexByte(h, '/'); slashIdx != -1 {
		h = h[:slashIdx]
	}
	h = strings.TrimRight(h, "/.")
	if idx := strings.Index(h, ":"); idx != -1 && !strings.Contains(h, "]") {
		h = h[:idx]
	}
	return strings.ToLower(strings.TrimSpace(h))
}

// isHostlessCnameAlias distinguishes Hostless shared ingress load-balancer targets
// (such as "gateway.hostless.cloud" or its Hetzner Helsinki IPs) and platform endpoints
// from an application's own public service domain (such as "my-app.hostless.app").
func isHostlessCnameAlias(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	if h == "gateway.hostless.cloud" ||
		strings.HasSuffix(h, ".gateway.hostless.cloud") ||
		h == "hostless.cloud" ||
		h == "hostless.app" ||
		h == "hostless.site" ||
		h == "hostless.dev" ||
		h == "apps.hostless.cloud" ||
		h == "api.hostless.cloud" ||
		h == "api.hostless.dev" ||
		h == "mcp.hostless.app" ||
		h == "web.hostless.cloud" ||
		h == "docs.hostless.cloud" ||
		h == "changelogs.hostless.cloud" ||
		h == "65.108.9.108" ||
		h == "65.109.57.177" {
		return true
	}
	return false
}

func isHostlessManagedDomain(h string) bool {
	h = cleanHost(h)
	if h == "" {
		return false
	}
	return isHostlessCnameAlias(h) ||
		strings.Contains(h, "hostless.app") ||
		strings.Contains(h, "hostless.cloud") ||
		strings.Contains(h, "hostless.site") ||
		strings.Contains(h, "hostless.dev") ||
		strings.HasSuffix(h, "-service") ||
		strings.HasSuffix(h, ".cluster.local") ||
		strings.HasSuffix(h, ".svc") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".local")
}

func isHostlessPublicDomain(h string) bool {
	h = cleanHost(h)
	if h == "" || isHostlessCnameAlias(h) {
		return false
	}
	return (strings.HasSuffix(h, ".hostless.app") ||
		strings.HasSuffix(h, ".apps.hostless.cloud") ||
		strings.HasSuffix(h, ".hostless.site")) &&
		!strings.HasSuffix(h, ".internal") &&
		!strings.HasSuffix(h, ".local") &&
		!strings.HasSuffix(h, ".cluster.local") &&
		!strings.HasSuffix(h, ".svc") &&
		!strings.HasSuffix(h, "-service")
}

func isFullHostlessServiceDomain(h string) bool {
	h = cleanHost(h)
	if h == "" || isHostlessCnameAlias(h) {
		return false
	}
	for _, suffix := range []string{".hostless.app", ".apps.hostless.cloud", ".hostless.site"} {
		if strings.HasSuffix(h, suffix) {
			sub := strings.TrimSuffix(h, suffix)
			return sub != "" && !strings.Contains(sub, ".")
		}
	}
	return false
}

func normalizeHostlessSubdomain(raw string) string {
	clean := cleanHost(raw)
	if clean == "" || isHostlessCnameAlias(clean) || net.ParseIP(clean) != nil {
		return ""
	}
	if isHostlessPublicDomain(clean) {
		return clean
	}
	if !strings.Contains(clean, ".") {
		candidate := clean + ".hostless.app"
		if isHostlessPublicDomain(candidate) {
			return candidate
		}
	}
	return ""
}

func normalizeRegion(raw string) string {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(s, "fi-hel") || strings.Contains(s, "helsinki") || strings.Contains(s, "finland") || strings.Contains(s, "hel") || strings.HasPrefix(s, "fi"):
		return "fi-hel1"
	case strings.Contains(s, "de-fra") || strings.Contains(s, "frankfurt") || strings.Contains(s, "falkenstein") || strings.Contains(s, "nuremberg") || strings.Contains(s, "germany") || strings.HasPrefix(s, "de"):
		return "de-fra1"
	case strings.Contains(s, "nl-ams") || strings.Contains(s, "europe-west4") || strings.Contains(s, "amsterdam") || strings.Contains(s, "nl"):
		return "europe-west4"
	case strings.Contains(s, "ch-") || strings.Contains(s, "zurich") || strings.Contains(s, "switzerland"):
		return "ch-central"
	case strings.Contains(s, "uk-lon") || strings.Contains(s, "london") || strings.Contains(s, "uk"):
		return "uk-lon1"
	case strings.Contains(s, "us-east") || strings.Contains(s, "virginia") || strings.Contains(s, "nyc") || strings.Contains(s, "chi"):
		return "us-east4"
	case strings.Contains(s, "us-west") || strings.Contains(s, "california") || strings.Contains(s, "oregon") || strings.Contains(s, "sjc"):
		return "us-west"
	case strings.Contains(s, "sg-sin") || strings.Contains(s, "singapore") || strings.Contains(s, "asia") || strings.Contains(s, "sin"):
		return "asia-southeast1"
	default:
		// Hostless Cloud gateway nodes (65.108.9.108 & 65.109.57.177) are hosted in Hetzner Helsinki (AS24940)
		return "fi-hel1"
	}
}

func resolveContainerPort() (string, int) {
	for _, key := range []string{"PORT", "BERMUDA_LISTEN_PORT", "SERVER_PORT", "APP_PORT"} {
		if raw := strings.TrimSpace(getEnv(key, "")); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 65535 {
				return strconv.Itoa(n), n
			}
		}
	}
	return defaultPort, 8080
}

func resolveInfrastructureDomains() (hlDomain, customDomain string) {
	subEnv := cleanHost(getEnv("HOSTLESS_DOMAIN", getEnv("HOSTLESS_PUBLIC_DOMAIN", getEnv("HOSTLESS_SUBDOMAIN", ""))))
	urlEnv := cleanHost(getEnv("HOSTLESS_URL", getEnv("HOSTLESS_APP_URL", getEnv("BERMUDA_HOSTLESS_DOMAIN", ""))))
	customEnv := cleanHost(getEnv("CUSTOM_DOMAIN", getEnv("BERMUDA_CUSTOM_DOMAIN", "")))

	for _, candidate := range []string{subEnv, urlEnv} {
		if norm := normalizeHostlessSubdomain(candidate); norm != "" {
			hlDomain = norm
			break
		}
	}

	for _, candidate := range []string{customEnv, urlEnv, subEnv} {
		if candidate != "" && !isHostlessManagedDomain(candidate) && normalizeHostlessSubdomain(candidate) == "" {
			customDomain = candidate
			break
		}
	}

	return hlDomain, customDomain
}

func bindDualListeners(listenCfg *net.ListenConfig, primaryPort string) ([]net.Listener, []string, error) {
	strictMode := strings.EqualFold(getEnv("BERMUDA_STRICT_PORT", "false"), "true")

	seenPorts := make(map[string]struct{}, 3)
	var portsToTry []string
	addPort := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, exists := seenPorts[p]; !exists {
			seenPorts[p] = struct{}{}
			portsToTry = append(portsToTry, p)
		}
	}

	addPort(primaryPort)
	if !strictMode {
		addPort(defaultPort)
		addPort(compatAltPort)
	}

	var listeners []net.Listener
	var boundAddrs []string
	var firstErr error

	for i, p := range portsToTry {
		addr := "0.0.0.0:" + p
		ln, err := listenCfg.Listen(context.Background(), "tcp", addr)
		if err != nil {
			if i == 0 {
				firstErr = err
				if strictMode {
					return nil, nil, err
				}
				log.Printf("[Gateway] Notice: Primary port :%s unavailable (%v); binding compatibility ports...", p, err)
			}
			continue
		}
		listeners = append(listeners, ln)
		boundAddrs = append(boundAddrs, ":"+p)
	}

	if len(listeners) == 0 {
		return nil, nil, firstErr
	}
	return listeners, boundAddrs, nil
}

func orchestrateCloudInfrastructure(
	ctx context.Context,
	sup *Supervisor,
	gw *Gateway,
	hl *HostlessClient,
	cf *CloudflareClient,
	initialHL string,
	initialCF string,
	region string,
) {
	for i := 0; i < 120 && !sup.IsReady(); i++ {
		if !sleepContext(ctx, 250*time.Millisecond) {
			return
		}
	}

	if !sleepContext(ctx, startupOrchestrationDelay) {
		return
	}

	hlDomain := normalizeHostlessSubdomain(initialHL)
	customDomain := cleanHost(initialCF)
	if curHL, curCF, _ := sup.GetInfrastructureDomains(); hlDomain == "" || customDomain == "" {
		if hlDomain == "" && isHostlessPublicDomain(curHL) {
			hlDomain = curHL
		}
		if customDomain == "" && curCF != "" && !isHostlessManagedDomain(curCF) {
			customDomain = curCF
		}
	}

	topologyUpdated := false
	loggedAfterDiscovery := false

	syncDomains := func(newHL, newCF string) {
		cleanHL := normalizeHostlessSubdomain(newHL)
		cleanCF := cleanHost(newCF)
		if isHostlessPublicDomain(cleanHL) {
			if hlDomain == "" || (!isFullHostlessServiceDomain(hlDomain) && isFullHostlessServiceDomain(cleanHL)) {
				if hlDomain != cleanHL {
					hlDomain = cleanHL
					topologyUpdated = true
				}
			}
		}
		if cleanCF != "" && !isHostlessManagedDomain(cleanCF) {
			if customDomain == "" || strings.HasSuffix(cleanCF, "."+customDomain) {
				if customDomain != cleanCF {
					customDomain = cleanCF
					topologyUpdated = true
				}
			}
		}
		sup.SetInfrastructureDomains(hlDomain, customDomain, region)
		gw.SetInfrastructureDomains(hlDomain, customDomain, region)
		if cf != nil {
			if hlDomain != "" {
				cf.SetHostlessOrigin(hlDomain)
			}
			if customDomain != "" {
				cf.SetPreferredDomain(customDomain)
			}
		}
		if hl != nil {
			if hlDomain != "" {
				hl.SetServiceDomain(hlDomain)
			}
			if customDomain != "" {
				hl.SetCustomDomain(customDomain)
			}
		}
	}

	if hl != nil && hl.IsConfigured() {
		if srvDom, err := hl.EnsureServiceDomain(ctx); err == nil && srvDom != "" {
			syncDomains(srvDom, "")
		} else if err != nil {
			log.Printf("[Hostless] Notice: Service domain lookup: %v", err)
		}

		if reg := hl.GetDiscoveredRegion(); reg != "" {
			region = normalizeRegion(reg)
			sup.SetInfrastructureDomains(hlDomain, customDomain, region)
			gw.SetInfrastructureDomains(hlDomain, customDomain, region)
		}

		if (sup.IsMasterKeyAutoGenerated() || sanitizeMasterKey(getEnv("BERMUDA_MASTER_KEY", getEnv("MASTER_KEY", ""))) == "") &&
			!strings.EqualFold(getEnv("BERMUDA_PERSIST_KEY", "true"), "false") {
			hl.PersistMasterKey(ctx, sup.MasterKey())
		}
	}

	if cf != nil && cf.Token != "" {
		probeCtx, probeCancel := context.WithTimeout(ctx, 12*time.Second)
		if cfDom, err := cf.FetchZoneDomain(probeCtx); err == nil && cfDom != "" {
			if customDomain == "" && !strings.HasPrefix(cfDom, "portal.") {
				cfDom = "portal." + cfDom
			}
			syncDomains(cf.GetHostlessOrigin(), cfDom)
		} else if err != nil {
			log.Printf("[Cloudflare] Notice: Zone domain discovery: %v", err)
		}
		probeCancel()
	}

	if topologyUpdated && ctx.Err() == nil {
		log.Printf("[Runtime] Synchronized Topology: HostlessDomain=%q | CloudflareDomain=%q | Region=%q",
			hlDomain, customDomain, region)
		sup.LogProvisioningLink("")
		loggedAfterDiscovery = true
	}

	var customDomInfo *HostlessCustomDomainInfo
	var cnameRecordID string
	var cfDNSProvisioned bool

	if customDomain != "" && (hl != nil || hlDomain != "" || cf != nil) {
		if hl != nil && hl.IsConfigured() {
			info, err := hl.EnsureCustomDomain(ctx, customDomain)
			if err != nil {
				log.Printf("[Hostless] Notice: Custom domain registration (%s): %v", customDomain, err)
			} else if info != nil {
				customDomInfo = info
				syncDomains(hl.GetServiceDomain(), info.Domain)
			}
		}
		if customDomInfo == nil {
			certState := "PENDING_TLS"
			isValid := probeCustomDomainTLS(ctx, customDomain, defaultHostlessIngressCNAME)
			if isValid {
				certState = "VALID"
			}
			customDomInfo = &HostlessCustomDomainInfo{
				Domain:            customDomain,
				CNAMETarget:       defaultHostlessIngressCNAME,
				CertificateStatus: certState,
				SSLReady:          isValid,
				RouteReady:        isValid,
				Ready:             isValid,
			}
		}
		if customDomInfo != nil && cf != nil && cf.Token != "" {
			recID, dnsErr := cf.ProvisionHostlessDNS(ctx, customDomInfo)
			if dnsErr != nil {
				log.Printf("[Cloudflare] Warning: Automated Hostless DNS provisioning: %v", dnsErr)
			} else {
				cnameRecordID = recID
				cfDNSProvisioned = true
				_ = sleepContext(ctx, dnsPropagationSettleDelay)
			}
		}
	}

	if cf != nil && cf.Token != "" && ctx.Err() == nil {
		cf.Tune(ctx)
		syncDomains(cf.GetHostlessOrigin(), cf.CachedZoneDomain())
	}

	autoOrange := !strings.EqualFold(getEnv("BERMUDA_CF_AUTO_ORANGE", "true"), "false")
	if cf != nil && customDomInfo != nil && !customDomInfo.IsCertificateValid() && autoOrange && ctx.Err() == nil {
		if cfDNSProvisioned || customDomInfo.RecordsVerified {
			log.Printf("[Hostless] Waiting for Let's Encrypt TLS & Route readiness on %s before enabling Cloudflare Orange Cloud...", customDomInfo.Domain)
			if hl != nil && hl.IsConfigured() {
				updatedInfo, valid := hl.WaitCustomDomainCertificate(ctx, customDomInfo.ID, customDomInfo.Domain, defaultHLCertPollWait)
				if valid && updatedInfo != nil {
					cf.PromoteCustomDomainToOrangeCloud(ctx, updatedInfo.Domain, updatedInfo.CNAMETarget, cnameRecordID)
				} else if ctx.Err() == nil {
					go watchAndPromoteCustomDomain(ctx, hl, cf, customDomInfo, cnameRecordID)
				}
			} else {
				go watchAndPromoteCustomDomain(ctx, nil, cf, customDomInfo, cnameRecordID)
			}
		} else if cf.GetZoneID() != "" {
			go watchAndPromoteCustomDomain(ctx, hl, cf, customDomInfo, cnameRecordID)
		}
	}

	if hl != nil && hl.IsConfigured() && ctx.Err() == nil {
		hl.TuneComputeAndNetwork(ctx)
	}

	if ctx.Err() == nil && !loggedAfterDiscovery && (topologyUpdated || hl != nil || cf != nil) {
		log.Printf("[Runtime] Synchronized Topology: HostlessDomain=%q | CloudflareDomain=%q | Region=%q",
			hlDomain, customDomain, region)
		sup.LogProvisioningLink("")
	}
}

func watchAndPromoteCustomDomain(
	parent context.Context,
	hl *HostlessClient,
	cf *CloudflareClient,
	info *HostlessCustomDomainInfo,
	cnameRecordID string,
) {
	ctx, cancel := context.WithTimeout(parent, 15*time.Minute)
	defer cancel()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if hl != nil && hl.IsConfigured() {
				latest, err := hl.FetchCustomDomainStatus(ctx, info.ID, info.Domain)
				if err == nil && latest != nil && latest.IsCertificateValid() {
					log.Printf("[Hostless] ✓ Deferred TLS & Route validation completed for %s (%s)",
						latest.Domain, latest.CertificateStatus)
					cf.PromoteCustomDomainToOrangeCloud(ctx, latest.Domain, latest.CNAMETarget, cnameRecordID)
					return
				}
			} else if probeCustomDomainTLS(ctx, info.Domain, info.CNAMETarget) {
				log.Printf("[Hostless] ✓ Direct Origin TLS + Route Identity verified for %s", info.Domain)
				cf.PromoteCustomDomainToOrangeCloud(ctx, info.Domain, info.CNAMETarget, cnameRecordID)
				return
			}
		}
	}
}

func teardown(
	srv *http.Server,
	gw *Gateway,
	sup *Supervisor,
	supCancel context.CancelFunc,
	cloudCancel context.CancelFunc,
	graceful bool,
) {
	hardDeadline := time.Now().Add(22 * time.Second)

	if cloudCancel != nil {
		cloudCancel()
	}

	gw.SetDraining()
	if graceful {
		log.Println("[Gateway] Stage 1/5: Health status set to 503 (traffic shedding)...")
		time.Sleep(drainPropagationWindow)
	}

	if graceful {
		log.Println("[Gateway] Stage 2/5: Draining HTTP listeners and active XHTTP streams...")
		httpDeadline := minTime(hardDeadline.Add(-7*time.Second), time.Now().Add(11*time.Second))
		httpCtx, cancelHTTP := context.WithDeadline(context.Background(), httpDeadline)
		if err := srv.Shutdown(httpCtx); err != nil {
			log.Printf("[Gateway] HTTP drain timeout (%v); closing listeners", err)
			_ = srv.Close()
		} else {
			log.Println("[Gateway] HTTP listeners drained cleanly")
		}
		cancelHTTP()

		log.Println("[Gateway] Stage 3/5: Waiting for active upgraded WebSocket tunnels...")
		tunnelDeadline := minTime(hardDeadline.Add(-5*time.Second), time.Now().Add(httpDrainTimeout))
		if tunnelDeadline.After(time.Now()) {
			tunnelCtx, cancelTunnel := context.WithDeadline(context.Background(), tunnelDeadline)
			gw.WaitTunnels(tunnelCtx)
			cancelTunnel()
		}
	} else {
		_ = srv.Close()
	}

	log.Println("[Gateway] Stage 4/5: Closing remaining sockets and idle pools...")
	gw.CloseTunnels()
	gw.CloseIdleBackendConns()

	log.Println("[Gateway] Stage 5/5: Stopping worker process group...")
	supCancel()
	remainingSupTime := time.Until(hardDeadline)
	if remainingSupTime <= 0 {
		remainingSupTime = 2 * time.Second
	}
	sup.Stop(remainingSupTime)
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)

	// Build-time pre-staging hook: invoked by hostless.yaml during the writable build phase
	// so router-worker and geo assets are baked into ./bin before the runtime rootfs is mounted read-only.
	for _, arg := range os.Args[1:] {
		if arg == "--prefetch-worker" || arg == "-prefetch-worker" {
			PrefetchWorkerDuringBuild()
			os.Exit(0)
		}
	}

	log.Println("[Gateway] Initializing BERMUDA PORTAL Edge Router (Hostless Cloud + Cloudflare Edition)...")

	gwMB, workerMB, compact := deriveMemoryBudget()
	procs := applyGOMAXPROCS()

	_ = syscall.Setenv("BERMUDA_WORKER_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_XRAY_MEM_MB", strconv.Itoa(workerMB))
	_ = syscall.Setenv("BERMUDA_WORKER_GOMAXPROCS", strconv.Itoa(procs))
	_ = syscall.Setenv("BERMUDA_XRAY_GOMAXPROCS", strconv.Itoa(procs))

	tierLabel := "STANDARD-1GB"
	if compact {
		tierLabel = "COMPACT-256MB-SAFE"
	}
	log.Printf("[Runtime] Resource budget calibrated [%s]: Gateway=%dMiB, Worker=%dMiB | GOMAXPROCS=%d",
		tierLabel, gwMB, workerMB, procs)

	sigCtx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stopSig()

	portStr, _ := resolveContainerPort()
	hlDomain, customDomain := resolveInfrastructureDomains()

	rawRegion := getEnv("BERMUDA_REGION", getEnv("HOSTLESS_REGION", getEnv("REGION", "")))
	region := normalizeRegion(rawRegion)

	// NewSupervisor initializes credentials, in-memory config, and subreaper in <1ms without
	// blocking on network I/O, allowing HTTP listeners to bind immediately on container boot
	// so Hostless's strict 1-second health check passes on the very first probe.
	sup := NewSupervisor()

	cfToken := sanitizeCloudflareToken(getEnv("CLOUDFLARE_API_TOKEN", getEnv("BERMUDA_CF_API_TOKEN", "")))
	cfZoneID := sanitizeExplicitCredential(getEnv("CLOUDFLARE_ZONE_ID", getEnv("BERMUDA_CF_ZONE_ID", "")))
	var cf *CloudflareClient
	if cfToken != "" {
		cf = NewCloudflareClient(cfToken, cfZoneID)
		if hlDomain != "" {
			cf.SetHostlessOrigin(hlDomain)
		}
		if customDomain != "" {
			cf.SetPreferredDomain(customDomain)
		}
	} else {
		log.Println("[Cloudflare] Notice: CLOUDFLARE_API_TOKEN unset. Edge auto-tuning bypassed.")
	}

	hlToken := sanitizeHostlessToken(getEnv("HOSTLESS_API_KEY", getEnv("HOSTLESS_TOKEN", getEnv("HOSTLESS_API_TOKEN", getEnv("BERMUDA_HOSTLESS_TOKEN", "")))))
	var hl *HostlessClient
	if hlToken != "" {
		hl = NewHostlessClient(hlToken)
		if hlDomain != "" {
			hl.SetServiceDomain(hlDomain)
		}
		if customDomain != "" {
			hl.SetCustomDomain(customDomain)
		}
	} else {
		log.Println("[Hostless] Notice: HOSTLESS_API_KEY unset. Hostless API self-provisioning bypassed.")
	}

	sup.SetInfrastructureDomains(hlDomain, customDomain, region)
	primaryLogDomain := customDomain
	if primaryLogDomain == "" {
		primaryLogDomain = hlDomain
	}
	if primaryLogDomain != "" {
		sup.SetPublicDomain(primaryLogDomain)
	}

	log.Printf("[Runtime] Initial Topology: HostlessDomain=%q | CloudflareDomain=%q | Region=%q",
		hlDomain, customDomain, region)

	gw := NewGateway(sup, cf, hlDomain, customDomain, region)
	gw.SetHostlessClient(hl)

	topologyUpdater := func(hlDom, cfDom string) {
		sup.SetInfrastructureDomains(hlDom, cfDom, region)
		gw.SetInfrastructureDomains(hlDom, cfDom, region)
	}
	if cf != nil {
		cf.SetTopologyCallback(topologyUpdater)
	}
	if hl != nil {
		hl.SetTopologyCallback(topologyUpdater)
	}

	maxHdrBytes := 32 << 10
	if compact {
		maxHdrBytes = 16 << 10
	}

	srv := &http.Server{
		Addr:              "0.0.0.0:" + portStr,
		Handler:           gw.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       0,
		WriteTimeout:      0,
		IdleTimeout:       16 * time.Minute,
		MaxHeaderBytes:    maxHdrBytes,
		ConnState:         gw.TrackConnState,
	}

	listenCfg := net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     edgeKeepAlivePeriod,
			Interval: edgeKeepAlivePeriod,
			Count:    4,
		},
		Control: func(network, address string, c syscall.RawConn) error {
			_ = c.Control(func(fd uintptr) {
				_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, tcpUserTimeoutOpt, 90000)
			})
			return nil
		},
	}

	// Bind HTTP listeners FIRST before starting worker bootstrap so Hostless's Kubernetes
	// health probe (1-second timeout) succeeds instantaneously.
	listeners, boundAddrs, err := bindDualListeners(&listenCfg, portStr)
	if err != nil {
		log.Fatalf("[Gateway] Fatal: Cannot bind HTTP listener on :%s: %v", portStr, err)
	}

	serverErrCh := make(chan error, len(listeners))
	log.Printf("[Gateway] Edge listeners active on %s (PID %d, GOMAXPROCS=%d)",
		strings.Join(boundAddrs, " & "), os.Getpid(), procs)

	for _, ln := range listeners {
		activeLn := ln
		go func() {
			if err := srv.Serve(activeLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
				select {
				case serverErrCh <- err:
				default:
				}
			}
		}()
	}

	supCtx, supCancel := context.WithCancel(context.Background())
	supErrCh := make(chan error, 1)
	go func() {
		supErrCh <- sup.Run(supCtx)
	}()

	go func() {
		select {
		case <-sup.BootstrapDone():
		case <-sigCtx.Done():
			return
		}
		runtime.GC()
		debug.FreeOSMemory()
		applyMemoryCeiling(gwMB, compact)
	}()

	cloudCtx, cloudCancel := context.WithCancel(sigCtx)
	defer cloudCancel()
	if hl != nil || cf != nil {
		go orchestrateCloudInfrastructure(cloudCtx, sup, gw, hl, cf, hlDomain, customDomain, region)
	}

	select {
	case err := <-serverErrCh:
		log.Printf("[Gateway] Fatal: HTTP server error: %v", err)
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case err := <-supErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("[Gateway] Fatal: Worker supervisor halted: %v", err)
		}
		teardown(srv, gw, sup, supCancel, cloudCancel, false)
		os.Exit(1)
	case <-sigCtx.Done():
		log.Println("[Gateway] Termination signal received. Initiating graceful teardown...")
	}

	teardown(srv, gw, sup, supCancel, cloudCancel, true)
	log.Println("[Gateway] BERMUDA PORTAL Edge Router shutdown complete. Exit 0.")
}
