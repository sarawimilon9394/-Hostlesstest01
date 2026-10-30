package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	cfAPIBase                  = "https://api.cloudflare.com/client/v4"
	defaultManagedHTTPDDoSID   = "4d21379b4f9f4bb088e0729962c8b3cf"
	defaultEdgeTuneTimeout     = 90 * time.Second
	defaultSingleReqTimeout    = 12 * time.Second
	defaultZoneDiscoverTimeout = 10 * time.Second
	bermudaHLCommentPrefix     = "bermuda-hl:"
	legacyBHCommentPrefix      = "bermuda-bh:"
	legacySNCommentPrefix      = "bermuda-sn:"
	legacyRNCommentPrefix      = "bermuda-rn:"
	legacyLCCommentPrefix      = "bermuda-lc:"
	legacyRWCommentPrefix      = "bermuda-rw:"
)

type cfAPIMsg struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfEnvelope[T any] struct {
	Success  bool       `json:"success"`
	Errors   []cfAPIMsg `json:"errors"`
	Messages []cfAPIMsg `json:"messages"`
	Result   T          `json:"result"`
}

type cfAPIError struct {
	StatusCode int
	Errors     []cfAPIMsg
}

func (e *cfAPIError) Error() string {
	return fmt.Sprintf("cloudflare api error (HTTP %d): %+v", e.StatusCode, e.Errors)
}

func (e *cfAPIError) IsInvalidToken() bool {
	for _, msg := range e.Errors {
		if msg.Code == 9109 || msg.Code == 6003 || msg.Code == 9106 {
			return true
		}
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "invalid access token") || strings.Contains(lower, "invalid request headers") {
			return true
		}
	}
	return false
}

func (e *cfAPIError) IsPermissionOrPlan() bool {
	if e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden {
		return true
	}
	for _, msg := range e.Errors {
		if msg.Code == 50001 || msg.Code == 1003 {
			return true
		}
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "unauthorized") ||
			strings.Contains(lower, "not allowed") ||
			strings.Contains(lower, "permission") ||
			strings.Contains(lower, "entitlement") ||
			strings.Contains(lower, "subscription") ||
			strings.Contains(lower, "plan") ||
			strings.Contains(lower, "exceeded the maximum number of rules") ||
			strings.Contains(lower, "out of 0") {
			return true
		}
	}
	return false
}

type cfZoneDetails struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type CloudflareClient struct {
	Token           string
	ZoneID          string
	apiBase         string
	preferredDomain string
	hostlessOrigin  string
	client          *http.Client
	mu              sync.RWMutex
	cachedZone      string
	holdGreyCloud   bool
	onTopology      func(hlDom, cfDom string)
}

func sanitizeCloudflareToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{"CLOUDFLARE_API_TOKEN", "BERMUDA_CF_API_TOKEN", "CF_API_TOKEN"} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	if len(s) > 7 && strings.EqualFold(s[:7], "bearer ") {
		s = strings.TrimSpace(s[7:])
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r > 126 {
			return -1
		}
		return r
	}, s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func NewCloudflareClient(token, zoneID string) *CloudflareClient {
	cleanTok := sanitizeCloudflareToken(token)
	cleanZone := sanitizeExplicitCredential(zoneID)
	hlDom, _ := resolveInfrastructureDomains()
	return &CloudflareClient{
		Token:          cleanTok,
		ZoneID:         cleanZone,
		apiBase:        cfAPIBase,
		hostlessOrigin: normalizeHostlessSubdomain(hlDom),
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func extractCommentHostlessDomain(comment string) string {
	comment = strings.TrimSpace(comment)
	lower := strings.ToLower(comment)
	for _, prefix := range []string{
		bermudaHLCommentPrefix,
		legacyBHCommentPrefix,
		legacySNCommentPrefix,
		legacyRNCommentPrefix,
		legacyLCCommentPrefix,
		legacyRWCommentPrefix,
	} {
		idx := strings.Index(lower, prefix)
		if idx == -1 {
			continue
		}
		rest := strings.TrimSpace(comment[idx+len(prefix):])
		if fields := strings.Fields(rest); len(fields) > 0 {
			rest = fields[0]
		}
		if pipeIdx := strings.IndexByte(rest, '|'); pipeIdx != -1 {
			rest = rest[:pipeIdx]
		}
		candidate := normalizeHostlessSubdomain(rest)
		if isFullHostlessServiceDomain(candidate) {
			return candidate
		}
	}
	return ""
}

func (c *CloudflareClient) SetTopologyCallback(fn func(hlDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *CloudflareClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	hl := c.hostlessOrigin
	cf := c.preferredDomain
	if cf == "" {
		cf = c.cachedZone
	}
	c.mu.RUnlock()
	if fn != nil {
		fn(hl, cf)
	}
}

func (c *CloudflareClient) SetPreferredDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isHostlessManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.preferredDomain = clean
	if c.cachedZone == "" || strings.HasSuffix(clean, "."+c.cachedZone) {
		c.cachedZone = clean
	}
	c.mu.Unlock()
}

func (c *CloudflareClient) SetHostlessOrigin(d string) {
	if c == nil {
		return
	}
	clean := normalizeHostlessSubdomain(d)
	if !isHostlessPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.hostlessOrigin == "" || isFullHostlessServiceDomain(clean) {
		c.hostlessOrigin = clean
	}
	c.mu.Unlock()
}

func (c *CloudflareClient) GetHostlessOrigin() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hostlessOrigin
}

func (c *CloudflareClient) GetZoneID() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ZoneID
}

func (c *CloudflareClient) SetHoldGreyCloud(hold bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.holdGreyCloud = hold
	c.mu.Unlock()
}

func (c *CloudflareClient) isHoldingGreyCloud() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.holdGreyCloud
}

func (c *CloudflareClient) baseURL() string {
	if c != nil && c.apiBase != "" {
		return c.apiBase
	}
	return cfAPIBase
}

func doCFRequest[T any](ctx context.Context, c *CloudflareClient, method, path string, body any) (T, error) {
	var zero T
	reqCtx, cancel := context.WithTimeout(ctx, defaultSingleReqTimeout)
	defer cancel()

	var reqBody io.Reader
	if body != nil {
		rawJSON, err := json.Marshal(body)
		if err != nil {
			return zero, fmt.Errorf("marshal payload: %w", err)
		}
		reqBody = bytes.NewReader(rawJSON)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, c.baseURL()+path, reqBody)
	if err != nil {
		return zero, fmt.Errorf("build request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "BERMUDA-Portal-EdgeOrchestrator/4.0 (Go-Standard-Library)")

	resp, err := c.client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()

	rawBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return zero, fmt.Errorf("read response body: %w", err)
	}

	var env cfEnvelope[T]
	if err := json.Unmarshal(rawBytes, &env); err != nil {
		return zero, &cfAPIError{
			StatusCode: resp.StatusCode,
			Errors: []cfAPIMsg{{
				Code:    resp.StatusCode,
				Message: string(rawBytes[:min(len(rawBytes), 256)]),
			}},
		}
	}

	if resp.StatusCode >= 400 || !env.Success {
		return zero, &cfAPIError{
			StatusCode: resp.StatusCode,
			Errors:     env.Errors,
		}
	}

	return env.Result, nil
}

func (c *CloudflareClient) discoverTopologyFromDNS(ctx context.Context, zoneID, zoneDomain string) {
	if zoneID == "" {
		return
	}
	recordsPath := "/zones/" + zoneID + "/dns_records?per_page=100"
	records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recordsPath, nil)
	if err != nil || len(records) == 0 {
		return
	}

	c.mu.RLock()
	prefDom := c.preferredDomain
	curHL := c.hostlessOrigin
	c.mu.RUnlock()

	var matchedCFHost string
	var matchedHLTarget string
	var commentHLTarget string

	for _, rec := range records {
		if savedHL := extractCommentHostlessDomain(rec.Comment); savedHL != "" {
			if commentHLTarget == "" || isFullHostlessServiceDomain(savedHL) {
				commentHLTarget = savedHL
			}
		}

		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		if recType != "CNAME" {
			continue
		}
		recName := cleanHost(rec.Name)
		recContent := cleanHost(rec.Content)

		if !isHostlessManagedDomain(recContent) {
			continue
		}

		if prefDom != "" && recName == prefDom {
			matchedCFHost = recName
			if isFullHostlessServiceDomain(recContent) {
				matchedHLTarget = recContent
			}
			break
		}
		if matchedCFHost == "" || recName == "portal."+zoneDomain || recName == zoneDomain {
			matchedCFHost = recName
			if isFullHostlessServiceDomain(recContent) {
				matchedHLTarget = recContent
			}
		}
	}

	updated := false
	c.mu.Lock()
	if matchedCFHost != "" {
		if c.preferredDomain == "" {
			c.preferredDomain = matchedCFHost
		}
		if c.cachedZone == "" || c.cachedZone == zoneDomain {
			c.cachedZone = matchedCFHost
		}
		updated = true
	}

	bestHL := curHL
	if !isFullHostlessServiceDomain(bestHL) {
		if isFullHostlessServiceDomain(commentHLTarget) {
			bestHL = commentHLTarget
		} else if isFullHostlessServiceDomain(matchedHLTarget) {
			bestHL = matchedHLTarget
		}
	}

	if bestHL != "" && bestHL != c.hostlessOrigin {
		c.hostlessOrigin = bestHL
		updated = true
		log.Printf("[Cloudflare] ✓ Auto-discovered Hostless App Subdomain from DNS: %s", bestHL)
	}
	c.mu.Unlock()

	if updated {
		c.notifyTopology()
	}
}

func (c *CloudflareClient) selectBestZone(ctx context.Context, zones []cfZoneDetails, prefDom string) cfZoneDetails {
	selected := zones[0]
	if prefDom != "" {
		for _, z := range zones {
			zName := strings.TrimSpace(strings.ToLower(z.Name))
			if zName == prefDom || strings.HasSuffix(prefDom, "."+zName) {
				return z
			}
		}
		return selected
	}

	if len(zones) > 1 {
		for _, z := range zones {
			recPath := "/zones/" + z.ID + "/dns_records?per_page=100"
			records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recPath, nil)
			if err != nil {
				continue
			}
			for _, rec := range records {
				if extractCommentHostlessDomain(rec.Comment) != "" || isHostlessManagedDomain(cleanHost(rec.Content)) {
					return z
				}
			}
		}
	}
	return selected
}

func (c *CloudflareClient) FetchZoneDomain(parent context.Context) (string, error) {
	if c == nil || c.Token == "" {
		return "", errors.New("cloudflare client not configured")
	}

	c.mu.RLock()
	if c.cachedZone != "" && c.ZoneID != "" && c.hostlessOrigin != "" {
		domain := c.cachedZone
		c.mu.RUnlock()
		return domain, nil
	}
	currentZoneID := c.ZoneID
	prefDom := c.preferredDomain
	c.mu.RUnlock()

	ctx, cancel := context.WithTimeout(parent, defaultZoneDiscoverTimeout)
	defer cancel()

	var zoneDomain string

	if currentZoneID == "" {
		zones, err := doCFRequest[[]cfZoneDetails](ctx, c, http.MethodGet, "/zones?status=active&per_page=50", nil)
		if err != nil {
			var apiErr *cfAPIError
			if errors.As(err, &apiErr) && apiErr.IsInvalidToken() {
				log.Printf("[Cloudflare] Hint: CLOUDFLARE_API_TOKEN (length=%d) was rejected by Cloudflare (Code 9109). Ensure you created a 'User API Token' via the CLOUDFLARE TOKEN button.", len(c.Token))
			}
			return "", fmt.Errorf("auto-discover zones query failed: %w", err)
		}
		if len(zones) == 0 {
			return "", errors.New("no active zones found under this cloudflare api token")
		}

		selected := c.selectBestZone(ctx, zones, prefDom)
		zoneDomain = strings.TrimSpace(strings.ToLower(selected.Name))
		currentZoneID = selected.ID

		c.mu.Lock()
		c.ZoneID = currentZoneID
		if c.cachedZone == "" {
			if prefDom != "" && (prefDom == zoneDomain || strings.HasSuffix(prefDom, "."+zoneDomain)) {
				c.cachedZone = prefDom
			} else {
				c.cachedZone = zoneDomain
			}
		}
		c.mu.Unlock()

		log.Printf("[Cloudflare] ✓ Auto-discovered Zone ID: %s for zone: %s (Total Active Zones: %d)",
			currentZoneID, zoneDomain, len(zones))
	} else {
		path := "/zones/" + currentZoneID
		res, err := doCFRequest[cfZoneDetails](ctx, c, http.MethodGet, path, nil)
		if err != nil {
			return "", fmt.Errorf("fetch zone details failed: %w", err)
		}

		zoneDomain = strings.TrimSpace(strings.ToLower(res.Name))
		if zoneDomain != "" {
			c.mu.Lock()
			if c.cachedZone == "" {
				if prefDom != "" && (prefDom == zoneDomain || strings.HasSuffix(prefDom, "."+zoneDomain)) {
					c.cachedZone = prefDom
				} else {
					c.cachedZone = zoneDomain
				}
			}
			c.mu.Unlock()
			log.Printf("[Cloudflare] ✓ Resolved Zone Domain for Zone %s: %s", currentZoneID, zoneDomain)
		}
	}

	c.discoverTopologyFromDNS(ctx, currentZoneID, zoneDomain)

	return c.CachedZoneDomain(), nil
}

func (c *CloudflareClient) CachedZoneDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.preferredDomain != "" {
		return c.preferredDomain
	}
	return c.cachedZone
}

type cfSettingResult struct {
	ID       string `json:"id"`
	Value    any    `json:"value"`
	Editable bool   `json:"editable"`
}

type cfSettingTarget struct {
	Name  string
	Path  string
	Value any
}

func (c *CloudflareClient) ensureSetting(ctx context.Context, target cfSettingTarget) bool {
	cur, err := doCFRequest[cfSettingResult](ctx, c, http.MethodGet, target.Path, nil)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && (apiErr.IsPermissionOrPlan() || apiErr.StatusCode == http.StatusNotFound) {
			log.Printf("[Cloudflare] Note: %s skipped (plan/permission restriction)", target.Name)
			return false
		}
		log.Printf("[Cloudflare] Warning: Read failed for %s: %v", target.Name, err)
		return false
	}

	if fmt.Sprint(cur.Value) == fmt.Sprint(target.Value) {
		log.Printf("[Cloudflare] ✓ %s: ALREADY OPTIMAL (%v)", target.Name, cur.Value)
		return false
	}

	if !cur.Editable {
		log.Printf("[Cloudflare] Note: %s is locked/read-only on this zone plan (current: %v)", target.Name, cur.Value)
		return false
	}

	payload := map[string]any{"value": target.Value}
	_, err = doCFRequest[cfSettingResult](ctx, c, http.MethodPatch, target.Path, payload)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Printf("[Cloudflare] Note: Patch skipped for %s (insufficient permissions/plan)", target.Name)
			return false
		}
		log.Printf("[Cloudflare] Warning: Patch failed for %s: %v", target.Name, err)
		return false
	}

	log.Printf("[Cloudflare] ✓ %s: ENFORCED -> %v", target.Name, target.Value)
	return true
}

type cfUniversalSSL struct {
	Enabled bool `json:"enabled"`
}

func (c *CloudflareClient) ensureUniversalSSL(ctx context.Context, zoneID string) bool {
	path := "/zones/" + zoneID + "/ssl/universal/settings"
	cur, err := doCFRequest[cfUniversalSSL](ctx, c, http.MethodGet, path, nil)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: Universal SSL check skipped (missing 'SSL and Certificates' permission)")
			return false
		}
		log.Printf("[Cloudflare] Note: Universal SSL query skipped: %v", err)
		return false
	}

	if cur.Enabled {
		log.Println("[Cloudflare] ✓ Universal Edge SSL Certificates: ALREADY ENABLED")
		return false
	}

	_, err = doCFRequest[cfUniversalSSL](ctx, c, http.MethodPatch, path, cfUniversalSSL{Enabled: true})
	if err != nil {
		log.Printf("[Cloudflare] Warning: Universal SSL enablement unapplied: %v", err)
		return false
	}

	log.Println("[Cloudflare] ✓ Universal Edge SSL Certificates: ENABLED")
	return true
}

type cfZoneDNSSettings struct {
	FlattenAllCNAMEs *bool `json:"flatten_all_cnames,omitempty"`
}

type cfDNSRecord struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	Proxied   bool   `json:"proxied"`
	Proxiable bool   `json:"proxiable"`
	TTL       int    `json:"ttl"`
	Comment   string `json:"comment,omitempty"`
}

// ProvisionHostlessDNS provisions the CNAME record (`portal.<domain> -> gateway.hostless.cloud`)
// starting on Grey Cloud (`Proxied: false`) while Hostless verifies DNS and issues the Let's Encrypt
// certificate, and then promotes to Orange Cloud (`Proxied: true`) once origin TLS is verified.
func (c *CloudflareClient) ProvisionHostlessDNS(ctx context.Context, info *HostlessCustomDomainInfo) (string, error) {
	if c == nil || c.Token == "" {
		return "", errors.New("cloudflare client not configured")
	}
	if info == nil || info.Domain == "" {
		return "", errors.New("incomplete hostless custom domain info for DNS provisioning")
	}

	cnameTarget := cleanHost(info.CNAMETarget)
	if cnameTarget == "" || isFullHostlessServiceDomain(cnameTarget) {
		cnameTarget = defaultHostlessIngressCNAME
	}

	zoneID := c.GetZoneID()
	if zoneID == "" {
		if _, err := c.FetchZoneDomain(ctx); err != nil {
			return "", err
		}
		zoneID = c.GetZoneID()
	}
	if zoneID == "" {
		return "", errors.New("missing cloudflare zone ID")
	}

	flattenTarget := cfSettingTarget{
		Name:  "Root CNAME Flattening (Apex Ingress Compatibility)",
		Path:  "/zones/" + zoneID + "/settings/cname_flattening",
		Value: "flatten_at_root",
	}
	c.ensureSetting(ctx, flattenTarget)

	recordsPath := "/zones/" + zoneID + "/dns_records?per_page=100"
	records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recordsPath, nil)
	if err != nil {
		return "", fmt.Errorf("fetch zone dns records: %w", err)
	}

	if info.VerificationHost != "" && info.VerificationToken != "" {
		c.upsertVerificationTXT(ctx, zoneID, records, info.VerificationHost, info.VerificationToken)
	}

	autoOrange := !strings.EqualFold(getEnv("BERMUDA_CF_AUTO_ORANGE", "true"), "false")
	wantProxied := info.IsCertificateValid() && autoOrange
	c.SetHoldGreyCloud(!wantProxied)

	targetHost := cleanHost(info.Domain)

	var existingCNAME *cfDNSRecord
	var conflictingRecords []cfDNSRecord

	for i := range records {
		rec := &records[i]
		if cleanHost(rec.Name) != targetHost {
			continue
		}
		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		switch recType {
		case "CNAME":
			existingCNAME = rec
		case "A", "AAAA":
			conflictingRecords = append(conflictingRecords, *rec)
		}
	}

	if len(conflictingRecords) > 0 && !strings.EqualFold(getEnv("BERMUDA_CF_REPLACE_CONFLICT_DNS", "true"), "false") {
		for _, conflict := range conflictingRecords {
			delPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, conflict.ID)
			if _, delErr := doCFRequest[map[string]any](ctx, c, http.MethodDelete, delPath, nil); delErr == nil {
				log.Printf("[Cloudflare] ✓ Removed conflicting %s record on %s (%s) to allow Hostless CNAME binding",
					conflict.Type, conflict.Name, conflict.Content)
			}
		}
	}

	hlOrigin := c.GetHostlessOrigin()
	var commentTag string
	if isFullHostlessServiceDomain(hlOrigin) {
		candidate := bermudaHLCommentPrefix + hlOrigin
		if len(candidate) <= 95 {
			commentTag = candidate
		}
	}

	if existingCNAME != nil {
		curTarget := cleanHost(existingCNAME.Content)
		curComment := existingCNAME.Comment
		if commentTag == "" {
			commentTag = curComment
		}

		if curTarget == cnameTarget && existingCNAME.Proxied == wantProxied && (commentTag == "" || curComment == commentTag) {
			log.Printf("[Cloudflare] ✓ Hostless CNAME Record (%s -> %s, Proxied=%v): ALREADY SYNCED",
				targetHost, cnameTarget, wantProxied)
			return existingCNAME.ID, nil
		}

		patchPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existingCNAME.ID)
		payload := map[string]any{
			"type":    "CNAME",
			"name":    targetHost,
			"content": cnameTarget,
			"proxied": wantProxied,
			"ttl":     1,
		}
		if commentTag != "" {
			payload["comment"] = commentTag
		}

		updated, patchErr := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, payload)
		if patchErr != nil && commentTag != "" {
			delete(payload, "comment")
			updated, patchErr = doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, payload)
		}
		if patchErr != nil {
			return existingCNAME.ID, fmt.Errorf("update hostless cname record: %w", patchErr)
		}

		log.Printf("[Cloudflare] ✓ Updated Hostless CNAME Record: %s -> %s (Proxied=%v)",
			targetHost, cnameTarget, updated.Proxied)
		return updated.ID, nil
	}

	postPath := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	payload := map[string]any{
		"type":    "CNAME",
		"name":    targetHost,
		"content": cnameTarget,
		"proxied": wantProxied,
		"ttl":     1,
	}
	if commentTag != "" {
		payload["comment"] = commentTag
	}

	created, postErr := doCFRequest[cfDNSRecord](ctx, c, http.MethodPost, postPath, payload)
	if postErr != nil && commentTag != "" {
		delete(payload, "comment")
		created, postErr = doCFRequest[cfDNSRecord](ctx, c, http.MethodPost, postPath, payload)
	}
	if postErr != nil {
		return "", fmt.Errorf("create hostless cname record: %w", postErr)
	}

	log.Printf("[Cloudflare] ✓ Auto-Created Hostless CNAME Record: %s -> %s (Proxied=%v)",
		targetHost, cnameTarget, created.Proxied)
	return created.ID, nil
}

func (c *CloudflareClient) upsertVerificationTXT(ctx context.Context, zoneID string, records []cfDNSRecord, verifyHost, verifyToken string) {
	cleanVerifyHost := cleanHost(verifyHost)
	cleanToken := strings.Trim(strings.TrimSpace(verifyToken), "\"")
	if cleanVerifyHost == "" || cleanToken == "" {
		return
	}

	var existingTXT *cfDNSRecord
	for i := range records {
		rec := &records[i]
		if strings.ToUpper(strings.TrimSpace(rec.Type)) != "TXT" {
			continue
		}
		if cleanHost(rec.Name) != cleanVerifyHost {
			continue
		}
		curVal := strings.Trim(strings.TrimSpace(rec.Content), "\"")
		if curVal == cleanToken {
			return
		}
		existingTXT = rec
	}

	payload := map[string]any{
		"type":    "TXT",
		"name":    cleanVerifyHost,
		"content": cleanToken,
		"ttl":     1,
	}

	if existingTXT != nil {
		patchPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, existingTXT.ID)
		if _, err := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, payload); err == nil {
			log.Printf("[Cloudflare] ✓ Updated Hostless Verification TXT Record: %s", cleanVerifyHost)
			return
		}
	}

	postPath := fmt.Sprintf("/zones/%s/dns_records", zoneID)
	if _, err := doCFRequest[cfDNSRecord](ctx, c, http.MethodPost, postPath, payload); err == nil {
		log.Printf("[Cloudflare] ✓ Auto-Created Hostless Verification TXT Record: %s", cleanVerifyHost)
	}
}

func (c *CloudflareClient) PromoteCustomDomainToOrangeCloud(ctx context.Context, targetDomain, cnameTarget, recordID string) bool {
	if c == nil || c.Token == "" {
		return false
	}
	if strings.EqualFold(getEnv("BERMUDA_CF_AUTO_ORANGE", "true"), "false") {
		return false
	}
	c.SetHoldGreyCloud(false)

	zoneID := c.GetZoneID()
	if zoneID == "" {
		return false
	}

	cleanDom := cleanHost(targetDomain)
	cleanTarget := cleanHost(cnameTarget)

	if recordID == "" || cleanTarget == "" {
		recordsPath := "/zones/" + zoneID + "/dns_records?per_page=100"
		if records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recordsPath, nil); err == nil {
			for _, rec := range records {
				if strings.EqualFold(rec.Type, "CNAME") && cleanHost(rec.Name) == cleanDom {
					recordID = rec.ID
					if cleanTarget == "" {
						cleanTarget = cleanHost(rec.Content)
					}
					if rec.Proxied {
						log.Printf("[Cloudflare] ✓ Custom Domain %s is already on Orange Cloud (Proxied=true)", cleanDom)
						return true
					}
					break
				}
			}
		}
	}

	if recordID == "" || cleanTarget == "" {
		return false
	}

	hlOrigin := c.GetHostlessOrigin()
	var commentTag string
	if isFullHostlessServiceDomain(hlOrigin) {
		candidate := bermudaHLCommentPrefix + hlOrigin
		if len(candidate) <= 95 {
			commentTag = candidate
		}
	}

	patchPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID)
	payload := map[string]any{
		"type":    "CNAME",
		"name":    cleanDom,
		"content": cleanTarget,
		"proxied": true,
		"ttl":     1,
	}
	if commentTag != "" {
		payload["comment"] = commentTag
	}

	_, err := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, payload)
	if err != nil && commentTag != "" {
		delete(payload, "comment")
		_, err = doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, payload)
	}
	if err != nil {
		log.Printf("[Cloudflare] Warning: Could not promote %s to Orange Cloud: %v", cleanDom, err)
		return false
	}

	log.Printf("[Cloudflare] ✓ Promoted %s (%s) -> ORANGE CLOUD ACTIVE (Proxied=true)", cleanDom, cleanTarget)
	return true
}

func (c *CloudflareClient) ensureDNSConfiguration(ctx context.Context, zoneID, zoneDomain string) bool {
	modified := false

	flattenTarget := cfSettingTarget{
		Name:  "Root CNAME Flattening (Apex Ingress Compatibility)",
		Path:  "/zones/" + zoneID + "/settings/cname_flattening",
		Value: "flatten_at_root",
	}
	if c.ensureSetting(ctx, flattenTarget) {
		modified = true
	}

	dnsSettingsPath := "/zones/" + zoneID + "/dns_settings"
	if curDNS, err := doCFRequest[cfZoneDNSSettings](ctx, c, http.MethodGet, dnsSettingsPath, nil); err == nil {
		if curDNS.FlattenAllCNAMEs != nil && *curDNS.FlattenAllCNAMEs {
			log.Println("[Cloudflare] ✓ Zone DNS Settings: CNAME Flattening Active")
		}
	}

	recordsPath := "/zones/" + zoneID + "/dns_records?per_page=100"
	records, err := doCFRequest[[]cfDNSRecord](ctx, c, http.MethodGet, recordsPath, nil)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: DNS record verification skipped (missing 'DNS: Edit' permission)")
			return modified
		}
		log.Printf("[Cloudflare] Note: DNS records list skipped: %v", err)
		return modified
	}

	c.mu.RLock()
	prefDom := c.preferredDomain
	hlOrigin := c.hostlessOrigin
	holdingGrey := c.holdGreyCloud
	c.mu.RUnlock()

	if hlOrigin == "" {
		hlOrigin, _ = resolveInfrastructureDomains()
	}

	topologyChanged := false

	for _, rec := range records {
		if savedHL := extractCommentHostlessDomain(rec.Comment); savedHL != "" && !isFullHostlessServiceDomain(hlOrigin) {
			hlOrigin = savedHL
			c.SetHostlessOrigin(savedHL)
			topologyChanged = true
		}

		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		if recType != "CNAME" && recType != "A" && recType != "AAAA" {
			continue
		}
		recName := cleanHost(rec.Name)
		recContent := cleanHost(rec.Content)

		isTargetHost := (recName == zoneDomain) || (prefDom != "" && recName == prefDom)
		isHostlessTarget := isHostlessManagedDomain(recContent) || (hlOrigin != "" && recContent == hlOrigin)

		if isHostlessManagedDomain(recContent) {
			if (hlOrigin == "" || !isFullHostlessServiceDomain(hlOrigin)) && isFullHostlessServiceDomain(recContent) {
				hlOrigin = recContent
				c.SetHostlessOrigin(recContent)
				topologyChanged = true
			}
			if prefDom == "" && recName != "" {
				prefDom = recName
				c.SetPreferredDomain(recName)
				topologyChanged = true
			}
		}

		wantComment := rec.Comment
		if isHostlessTarget && isFullHostlessServiceDomain(hlOrigin) {
			expectedTag := bermudaHLCommentPrefix + hlOrigin
			if extractCommentHostlessDomain(rec.Comment) != hlOrigin && len(expectedTag) <= 95 {
				wantComment = expectedTag
			}
		}

		needsProxyPatch := !holdingGrey && (isTargetHost || isHostlessTarget) && rec.Proxiable && !rec.Proxied
		needsCommentPatch := wantComment != rec.Comment

		if needsProxyPatch || needsCommentPatch {
			patchPath := fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, rec.ID)
			targetProxied := rec.Proxied
			if needsProxyPatch {
				targetProxied = true
			}
			patchPayload := map[string]any{
				"type":    rec.Type,
				"name":    rec.Name,
				"content": rec.Content,
				"proxied": targetProxied,
				"ttl":     1,
			}
			if needsCommentPatch {
				patchPayload["comment"] = wantComment
			}
			if _, patchErr := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, patchPayload); patchErr == nil {
				if needsProxyPatch {
					log.Printf("[Cloudflare] ✓ DNS Record %s (%s -> %s): ENFORCED ORANGE CLOUD (Proxied=true)",
						rec.Name, rec.Type, rec.Content)
					modified = true
				}
			} else if needsProxyPatch && needsCommentPatch {
				delete(patchPayload, "comment")
				if _, retryErr := doCFRequest[cfDNSRecord](ctx, c, http.MethodPatch, patchPath, patchPayload); retryErr == nil {
					log.Printf("[Cloudflare] ✓ DNS Record %s (%s -> %s): ENFORCED ORANGE CLOUD (Proxied=true)",
						rec.Name, rec.Type, rec.Content)
					modified = true
				} else {
					log.Printf("[Cloudflare] Note: Could not enable proxy on DNS record %s: %v", rec.Name, retryErr)
				}
			} else if needsProxyPatch {
				log.Printf("[Cloudflare] Note: Could not enable proxy on DNS record %s: %v", rec.Name, patchErr)
			}
		} else if (isTargetHost || isHostlessTarget) && rec.Proxied {
			log.Printf("[Cloudflare] ✓ DNS Record %s (%s -> %s): ORANGE CLOUD ACTIVE (Proxied=true)",
				rec.Name, rec.Type, rec.Content)
		}
	}

	if topologyChanged {
		c.notifyTopology()
	}

	return modified
}

type cfURLNormalization struct {
	Type  string `json:"type"`
	Scope string `json:"scope"`
}

func (c *CloudflareClient) ensureURLNormalization(ctx context.Context, zoneID string) bool {
	path := "/zones/" + zoneID + "/url_normalization"
	cur, err := doCFRequest[cfURLNormalization](ctx, c, http.MethodGet, path, nil)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: URL Normalization check skipped (missing 'Sanitize: Edit' permission)")
			return false
		}
		log.Printf("[Cloudflare] Note: URL Normalization read skipped: %v", err)
		return false
	}

	if cur.Type == "cloudflare" && (cur.Scope == "incoming" || cur.Scope == "none") {
		log.Printf("[Cloudflare] ✓ URL Normalization (Sanitize): ALREADY OPTIMAL (type=%s, scope=%s)", cur.Type, cur.Scope)
		return false
	}

	target := cfURLNormalization{
		Type:  "cloudflare",
		Scope: "incoming",
	}
	if _, err := doCFRequest[cfURLNormalization](ctx, c, http.MethodPut, path, target); err != nil {
		log.Printf("[Cloudflare] Note: URL Normalization update skipped: %v", err)
		return false
	}

	log.Println("[Cloudflare] ✓ URL Normalization (Sanitize): ENFORCED -> scope=incoming (Origin URI Preserved)")
	return true
}

type cfBotManagement struct {
	FightMode        *bool  `json:"fight_mode,omitempty"`
	EnableJS         *bool  `json:"enable_js,omitempty"`
	AIBotsProtection string `json:"ai_bots_protection,omitempty"`
}

func (c *CloudflareClient) tuneBotAndCrawlManagement(ctx context.Context, zoneID string) bool {
	path := "/zones/" + zoneID + "/bot_management"

	cur, err := doCFRequest[cfBotManagement](ctx, c, http.MethodGet, path, nil)
	if err == nil {
		fightOff := cur.FightMode != nil && !*cur.FightMode
		jsOff := cur.EnableJS != nil && !*cur.EnableJS
		aiBlocked := cur.AIBotsProtection == "block"
		if fightOff && jsOff && aiBlocked {
			log.Println("[Cloudflare] ✓ Bot Management & AI Crawl Control: ALREADY OPTIMAL (BFM=off, JSD=off, AIBots=block)")
			return false
		}
	}

	falseVal := false
	fullPayload := cfBotManagement{
		FightMode:        &falseVal,
		EnableJS:         &falseVal,
		AIBotsProtection: "block",
	}

	if _, err := doCFRequest[cfBotManagement](ctx, c, http.MethodPut, path, fullPayload); err == nil {
		log.Println("[Cloudflare] ✓ Bot Management & AI Crawl Control: ENFORCED (BFM=off, JSD=off, AIBots=block)")
		return true
	}

	fallbackJSD := cfBotManagement{
		FightMode: &falseVal,
		EnableJS:  &falseVal,
	}
	if _, err := doCFRequest[cfBotManagement](ctx, c, http.MethodPut, path, fallbackJSD); err == nil {
		log.Println("[Cloudflare] ✓ Bot Fight Mode & JS Detection: DISABLED (Standard L7 Routing Preserved)")
		return true
	}

	fallbackBFM := cfBotManagement{
		FightMode: &falseVal,
	}
	if _, err := doCFRequest[cfBotManagement](ctx, c, http.MethodPut, path, fallbackBFM); err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: Bot Management update skipped (missing permission or plan restriction)")
			return false
		}
		log.Printf("[Cloudflare] Note: Bot Management update unapplied: %v", err)
		return false
	}

	log.Println("[Cloudflare] ✓ Bot Fight Mode: DISABLED")
	return true
}

type cfManagedHeaderItem struct {
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
}

type cfManagedHeadersPayload struct {
	ManagedRequestHeaders  []cfManagedHeaderItem `json:"managed_request_headers,omitempty"`
	ManagedResponseHeaders []cfManagedHeaderItem `json:"managed_response_headers,omitempty"`
}

func (c *CloudflareClient) ensureManagedHeaders(ctx context.Context, zoneID string) bool {
	path := "/zones/" + zoneID + "/managed_headers"
	cur, err := doCFRequest[cfManagedHeadersPayload](ctx, c, http.MethodGet, path, nil)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: Managed Headers check skipped (missing 'Managed Headers: Edit' permission)")
			return false
		}
		log.Printf("[Cloudflare] Note: Managed Headers read skipped: %v", err)
		return false
	}

	var reqUpdates []cfManagedHeaderItem
	for _, h := range cur.ManagedRequestHeaders {
		if h.ID == "remove_visitor_ip_headers" && h.Enabled {
			reqUpdates = append(reqUpdates, cfManagedHeaderItem{ID: h.ID, Enabled: false})
		}
	}

	var respUpdates []cfManagedHeaderItem
	for _, h := range cur.ManagedResponseHeaders {
		if (h.ID == "add_security_headers" || h.ID == "remove_x-powered-by_header") && h.Enabled {
			respUpdates = append(respUpdates, cfManagedHeaderItem{ID: h.ID, Enabled: false})
		}
	}

	if len(reqUpdates) == 0 && len(respUpdates) == 0 {
		log.Println("[Cloudflare] ✓ Managed Transforms: ALREADY OPTIMAL (Client IP & Response Headers Preserved)")
		return false
	}

	patch := cfManagedHeadersPayload{
		ManagedRequestHeaders:  reqUpdates,
		ManagedResponseHeaders: respUpdates,
	}
	if _, err := doCFRequest[cfManagedHeadersPayload](ctx, c, http.MethodPatch, path, patch); err != nil {
		log.Printf("[Cloudflare] Note: Managed Transforms patch skipped: %v", err)
		return false
	}

	log.Println("[Cloudflare] ✓ Managed Transforms: ENFORCED (Disabled conflicting header mutations)")
	return true
}

type CFRule struct {
	ID               string         `json:"id,omitempty"`
	Ref              string         `json:"ref,omitempty"`
	Description      string         `json:"description,omitempty"`
	Expression       string         `json:"expression"`
	Action           string         `json:"action"`
	ActionParameters map[string]any `json:"action_parameters,omitempty"`
	Enabled          bool           `json:"enabled"`
}

type CFRuleset struct {
	ID    string   `json:"id,omitempty"`
	Rules []CFRule `json:"rules"`
}

func isMatchingRuleRef(existingRef, wantRef string) bool {
	if existingRef == wantRef {
		return true
	}
	suffix := strings.TrimPrefix(wantRef, "bermuda-")
	legacyPrefix := joinParts("ste", "alth-gw-")
	return suffix != "" && existingRef == legacyPrefix+suffix
}

func (c *CloudflareClient) upsertRule(ctx context.Context, phase string, want CFRule) (bool, error) {
	zoneID := c.GetZoneID()
	if zoneID == "" {
		return false, errors.New("missing zone id for ruleset update")
	}

	basePath := "/zones/" + zoneID + "/rulesets"
	entrypointPath := basePath + "/phases/" + phase + "/entrypoint"

	rs, err := doCFRequest[CFRuleset](ctx, c, http.MethodGet, entrypointPath, nil)
	var apiErr *cfAPIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
		_, err = doCFRequest[CFRuleset](ctx, c, http.MethodPut, entrypointPath, CFRuleset{
			Rules: []CFRule{want},
		})
		if err == nil {
			log.Printf("[Cloudflare] ✓ Phase %q Rule %q: INITIALIZED & ACTIVE", phase, want.Ref)
			return true, nil
		}
		return false, err
	}
	if err != nil {
		return false, err
	}

	for _, rule := range rs.Rules {
		if !isMatchingRuleRef(rule.Ref, want.Ref) && (want.Ref != "" || rule.Action != want.Action) {
			continue
		}

		a, _ := json.Marshal([]any{rule.Ref, rule.Expression, rule.Action, rule.ActionParameters, rule.Enabled})
		b, _ := json.Marshal([]any{want.Ref, want.Expression, want.Action, want.ActionParameters, want.Enabled})
		if bytes.Equal(a, b) {
			log.Printf("[Cloudflare] ✓ Phase %q Rule %q: ALREADY CONFIGURED (Idempotent match)", phase, want.Ref)
			return false, nil
		}

		patchPath := fmt.Sprintf("%s/%s/rules/%s", basePath, rs.ID, rule.ID)
		_, err = doCFRequest[CFRule](ctx, c, http.MethodPatch, patchPath, want)
		if err == nil {
			log.Printf("[Cloudflare] ✓ Phase %q Rule %q: UPDATED IN-PLACE", phase, want.Ref)
			return true, nil
		}
		return false, err
	}

	postPath := fmt.Sprintf("%s/%s/rules", basePath, rs.ID)
	_, err = doCFRequest[CFRule](ctx, c, http.MethodPost, postPath, want)
	if err == nil {
		log.Printf("[Cloudflare] ✓ Phase %q Rule %q: CREATED & ACTIVE", phase, want.Ref)
		return true, nil
	}
	return false, err
}

func (c *CloudflareClient) tuneHTTPDDoS(ctx context.Context, zoneID string) bool {
	phase := "ddos_l7"
	entrypointPath := "/zones/" + zoneID + "/rulesets/phases/" + phase + "/entrypoint"

	managedID := defaultManagedHTTPDDoSID
	if rs, err := doCFRequest[CFRuleset](ctx, c, http.MethodGet, entrypointPath, nil); err == nil {
		for _, r := range rs.Rules {
			if r.Action == "execute" && r.ActionParameters != nil {
				if idStr, ok := r.ActionParameters["id"].(string); ok && idStr != "" {
					managedID = idStr
				}
				if ov, ok := r.ActionParameters["overrides"].(map[string]any); ok {
					if lvl, ok := ov["sensitivity_level"].(string); ok && (lvl == "low" || lvl == "eoff") {
						log.Printf("[Cloudflare] ✓ Phase %q Sensitivity Override: ALREADY OPTIMAL (%s)", phase, lvl)
						return false
					}
				}
			}
		}
	}

	ddosRule := CFRule{
		Ref:         "bermuda-ddos-l7-tune",
		Description: "BERMUDA PORTAL L7 Stream Sensitivity Calibration",
		Expression:  "true",
		Action:      "execute",
		ActionParameters: map[string]any{
			"id": managedID,
			"overrides": map[string]any{
				"sensitivity_level": "low",
			},
		},
		Enabled: true,
	}

	_, err := doCFRequest[CFRuleset](ctx, c, http.MethodPut, entrypointPath, CFRuleset{
		Rules: []CFRule{ddosRule},
	})
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: HTTP DDoS L7 calibration skipped (missing permission or plan restriction)")
			return false
		}
		log.Printf("[Cloudflare] Note: HTTP DDoS L7 override unapplied: %v", err)
		return false
	}

	log.Printf("[Cloudflare] ✓ Phase %q Sensitivity Override: ENFORCED -> low (Multiplexed stream safe)", phase)
	return true
}

func buildApiPathExpression() string {
	pXH := strings.TrimSpace(getEnv("BERMUDA_PATH_XH", "/api/v1/sync"))
	pWS := strings.TrimSpace(getEnv("BERMUDA_PATH_WS", "/api/v1/live"))
	pTR := strings.TrimSpace(getEnv("BERMUDA_PATH_TR", "/api/v1/gateway"))

	if strings.HasPrefix(pXH, "/api/v1/") && strings.HasPrefix(pWS, "/api/v1/") && strings.HasPrefix(pTR, "/api/v1/") {
		return `starts_with(http.request.uri.path, "/api/v1/") or starts_with(http.request.uri.path, "/.well-known/acme-challenge/")`
	}

	seen := make(map[string]struct{}, 4)
	var parts []string
	for _, p := range []string{pXH, pWS, pTR, "/.well-known/acme-challenge/"} {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		parts = append(parts, fmt.Sprintf(`starts_with(http.request.uri.path, %q)`, p))
	}
	if len(parts) == 0 {
		return `starts_with(http.request.uri.path, "/api/v1/")`
	}
	return strings.Join(parts, " or ")
}

func (c *CloudflareClient) purgeEdgeCache(ctx context.Context, zoneID string) {
	path := "/zones/" + zoneID + "/purge_cache"
	payload := map[string]bool{"purge_everything": true}
	_, err := doCFRequest[map[string]any](ctx, c, http.MethodPost, path, payload)
	if err != nil {
		var apiErr *cfAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Println("[Cloudflare] Note: Edge Cache Purge skipped (missing 'Cache Purge' permission)")
			return
		}
		log.Printf("[Cloudflare] Note: Edge Cache Purge unapplied: %v", err)
		return
	}
	log.Println("[Cloudflare] ✓ Edge Cache Purge: EXECUTED (Stale artifacts evicted)")
}

func (c *CloudflareClient) Tune(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, defaultEdgeTuneTimeout)
	defer cancel()

	domainName, err := c.FetchZoneDomain(ctx)
	if err != nil {
		log.Printf("[Cloudflare] Error: Could not resolve zone details: %v. Aborting edge tuning.", err)
		return
	}

	zoneID := c.GetZoneID()
	log.Printf("[Cloudflare] Commencing Enterprise Edge Tuning for Zone %s (Domain: %s)...", zoneID, domainName)

	anyChanged := false

	if ctx.Err() == nil {
		if c.ensureUniversalSSL(ctx, zoneID) {
			anyChanged = true
		}
	}
	if ctx.Err() == nil {
		if c.ensureDNSConfiguration(ctx, zoneID, domainName) {
			anyChanged = true
		}
	}
	if ctx.Err() == nil {
		if c.ensureURLNormalization(ctx, zoneID) {
			anyChanged = true
		}
	}

	echTarget := strings.ToLower(strings.TrimSpace(getEnv("BERMUDA_CF_ECH", "on")))
	if echTarget != "off" {
		echTarget = "on"
	}

	standardSettings := []cfSettingTarget{
		{
			Name:  "SSL/TLS Encryption Mode (Full Origin Enforcement)",
			Path:  "/zones/" + zoneID + "/settings/ssl",
			Value: "full",
		},
		{
			Name:  "TLS 1.3 + Zero-RTT Edge Cipher Pipeline",
			Path:  "/zones/" + zoneID + "/settings/tls_1_3",
			Value: "zrt",
		},
		{
			Name:  "Minimum TLS Version 1.3 (Modern Cipher Enforcement)",
			Path:  "/zones/" + zoneID + "/settings/min_tls_version",
			Value: "1.3",
		},
		{
			Name:  "0-RTT Connection Resumption (Zero-Lag Reconnect)",
			Path:  "/zones/" + zoneID + "/settings/0rtt",
			Value: "on",
		},
		{
			Name:  "Encrypted Client Hello (ECH TLS 1.3 Extension)",
			Path:  "/zones/" + zoneID + "/settings/ech",
			Value: echTarget,
		},
		{
			Name:  "IPv6 Edge Ingress Compatibility (Happy Eyeballs)",
			Path:  "/zones/" + zoneID + "/settings/ipv6",
			Value: "on",
		},
		{
			Name:  "WebSockets L7 Support (Persistent Duplex Streams)",
			Path:  "/zones/" + zoneID + "/settings/websockets",
			Value: "on",
		},
		{
			Name:  "HTTP/2 to Edge (Stream Multiplexing Acceleration)",
			Path:  "/zones/" + zoneID + "/settings/http2",
			Value: "on",
		},
		{
			Name:  "HTTP/2 Stream Prioritization (Multiplexed Scheduling)",
			Path:  "/zones/" + zoneID + "/settings/h2_prioritization",
			Value: "on",
		},
		{
			Name:  "HTTP/3 QUIC (Line-Rate UDP Protocol)",
			Path:  "/zones/" + zoneID + "/settings/http3",
			Value: "on",
		},
		{
			Name:  "Opportunistic Encryption (ALPN Upgrade Pipeline)",
			Path:  "/zones/" + zoneID + "/settings/opportunistic_encryption",
			Value: "on",
		},
		{
			Name:  "Early Hints (RFC 8297 Preload Acceleration)",
			Path:  "/zones/" + zoneID + "/settings/early_hints",
			Value: "on",
		},
		{
			Name:  "Brotli Compression (Static Content Delivery)",
			Path:  "/zones/" + zoneID + "/settings/brotli",
			Value: "on",
		},
		{
			Name:  "Security Level (Challenge Mitigation)",
			Path:  "/zones/" + zoneID + "/settings/security_level",
			Value: "essentially_off",
		},
		{
			Name:  "Browser Integrity Check (Permit Non-Browser Core)",
			Path:  "/zones/" + zoneID + "/settings/browser_check",
			Value: "off",
		},
		{
			Name:  "Email Obfuscation (Prevent Stream Byte Mutation)",
			Path:  "/zones/" + zoneID + "/settings/email_obfuscation",
			Value: "off",
		},
		{
			Name:  "Rocket Loader (Prevent HTML/Stream Script Injection)",
			Path:  "/zones/" + zoneID + "/settings/rocket_loader",
			Value: "off",
		},
		{
			Name:  "Automatic HTTPS Rewrites (Prevent Payload Mutation)",
			Path:  "/zones/" + zoneID + "/settings/automatic_https_rewrites",
			Value: "off",
		},
		{
			Name:  "Always Online (Disable Stale Interstitial Pages)",
			Path:  "/zones/" + zoneID + "/settings/always_online",
			Value: "off",
		},
		{
			Name:  "Speed Brain (Disable Speculative Prefetch Noise)",
			Path:  "/zones/" + zoneID + "/settings/speed_brain",
			Value: "off",
		},
		{
			Name:  "Smart Tiered Caching Topology (Backbone Fiber Routing)",
			Path:  "/zones/" + zoneID + "/cache/tiered_cache_smart_topology_enable",
			Value: "on",
		},
	}

	for _, setting := range standardSettings {
		if ctx.Err() != nil {
			log.Println("[Cloudflare] Edge tuning context cancelled/timed out")
			return
		}
		if c.ensureSetting(ctx, setting) {
			anyChanged = true
		}
	}

	if ctx.Err() == nil {
		if c.tuneBotAndCrawlManagement(ctx, zoneID) {
			anyChanged = true
		}
	}

	if ctx.Err() == nil {
		if c.ensureManagedHeaders(ctx, zoneID) {
			anyChanged = true
		}
	}

	pathExpr := buildApiPathExpression()

	type phaseRuleSpec struct {
		Phase        string
		Name         string
		Rule         CFRule
		FallbackExpr string
	}

	phaseSpecs := []phaseRuleSpec{
		{
			Phase: "http_request_origin",
			Name:  "Origin Port Mapping Rule (2053/2083/2087/2096/8443 -> Origin 443)",
			Rule: CFRule{
				Ref:         "bermuda-origin-port-map",
				Description: "BERMUDA PORTAL Multi-Port Edge Ingress to Hostless Origin 443 Routing",
				Expression:  "cf.edge.server_port in {2053 2083 2087 2096 8443}",
				Action:      "route",
				ActionParameters: map[string]any{
					"origin": map[string]any{
						"port": 443,
					},
				},
				Enabled: true,
			},
			FallbackExpr: "true",
		},
		{
			Phase: "http_request_cache_settings",
			Name:  "Cache Bypass Rule",
			Rule: CFRule{
				Ref:         "bermuda-cache-bypass",
				Description: "BERMUDA PORTAL API Stream & ACME HTTP-01 Zero-Latency Cache Bypass",
				Expression:  pathExpr,
				Action:      "set_cache_settings",
				ActionParameters: map[string]any{
					"cache": false,
				},
				Enabled: true,
			},
		},
		{
			Phase: "http_response_compression",
			Name:  "Response Compression Bypass Rule (Zero-Buffering Stream)",
			Rule: CFRule{
				Ref:         "bermuda-compression-bypass",
				Description: "BERMUDA PORTAL Realtime Stream Zero-Buffering Compression Bypass",
				Expression:  pathExpr,
				Action:      "compress_response",
				ActionParameters: map[string]any{
					"algorithms": []map[string]string{
						{"name": "none"},
					},
				},
				Enabled: true,
			},
		},
		{
			Phase: "http_config_settings",
			Name:  "Config Isolation Rule (Pure Binary Pipe)",
			Rule: CFRule{
				Ref:         "bermuda-config-bypass",
				Description: "BERMUDA PORTAL API Stream & ACME Challenge Inspection Bypass",
				Expression:  pathExpr,
				Action:      "set_config",
				ActionParameters: map[string]any{
					"bic":                      false,
					"email_obfuscation":        false,
					"rocket_loader":            false,
					"automatic_https_rewrites": false,
					"security_level":           "essentially_off",
				},
				Enabled: true,
			},
		},
		{
			Phase: "http_request_firewall_custom",
			Name:  "Zone L7 Policy Exemption Rule (API Stream Continuity)",
			Rule: CFRule{
				Ref:         "bermuda-waf-bypass",
				Description: "BERMUDA PORTAL API Stream & ACME HTTP-01 Policy Exemption",
				Expression:  pathExpr,
				Action:      "skip",
				ActionParameters: map[string]any{
					"phases": []string{
						"http_ratelimit",
						"http_request_sbfm",
						"http_request_firewall_managed",
					},
					"products": []string{
						"zoneLockdown",
						"uaBlock",
						"bic",
						"hot",
						"securityLevel",
						"rateLimit",
						"waf",
					},
				},
				Enabled: true,
			},
		},
		{
			Phase: "http_response_headers_transform",
			Name:  "Response Header Transform Rule (Hostless & Hetzner Origin Header Scrubbing)",
			Rule: CFRule{
				Ref:         "bermuda-header-sanitize",
				Description: "BERMUDA PORTAL Hostless Origin Header Scrubbing for Pure OpenResty Camouflage",
				Expression:  "true",
				Action:      "rewrite",
				ActionParameters: map[string]any{
					"headers": map[string]any{
						"x-hostless-request-id":         map[string]string{"operation": "remove"},
						"x-request-id":                  map[string]string{"operation": "remove"},
						"alt-svc":                       map[string]string{"operation": "remove"},
						"x-envoy-upstream-service-time": map[string]string{"operation": "remove"},
						"x-envoy-decorator-operation":   map[string]string{"operation": "remove"},
						"x-powered-by":                  map[string]string{"operation": "remove"},
						"via":                           map[string]string{"operation": "remove"},
					},
				},
				Enabled: true,
			},
		},
	}

	for _, spec := range phaseSpecs {
		if ctx.Err() != nil {
			break
		}
		changed, err := c.upsertRule(ctx, spec.Phase, spec.Rule)
		if err != nil && spec.FallbackExpr != "" {
			fallbackRule := spec.Rule
			fallbackRule.Expression = spec.FallbackExpr
			changed, err = c.upsertRule(ctx, spec.Phase, fallbackRule)
		}
		if err != nil {
			var apiErr *cfAPIError
			if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
				log.Printf("[Cloudflare] Note: %s (%s) skipped (plan quota/permission restriction)", spec.Name, spec.Phase)
			} else {
				log.Printf("[Cloudflare] Note: %s (%s) unapplied: %v", spec.Name, spec.Phase, err)
			}
			continue
		}
		if changed {
			anyChanged = true
		}
	}

	if ctx.Err() == nil {
		if c.tuneHTTPDDoS(ctx, zoneID) {
			anyChanged = true
		}
	}

	forcePurge := strings.EqualFold(getEnv("BERMUDA_CF_FORCE_PURGE", "false"), "true")
	if ctx.Err() == nil && (anyChanged || forcePurge) {
		c.purgeEdgeCache(ctx, zoneID)
	}

	log.Printf("[Cloudflare] Edge Tuning sequence concluded successfully for Zone %s (Domain: %s)", zoneID, c.CachedZoneDomain())
}
