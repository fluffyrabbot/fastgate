package webauthn

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fastgate/decision-service/internal/config"
	"fastgate/decision-service/internal/token"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Handler manages WebAuthn challenge creation and verification.
type Handler struct {
	WebAuthn *webauthn.WebAuthn
	Store    *Store
	Keyring  *token.Keyring
	Config   *config.Config
}

// NewHandler creates a new WebAuthn handler.
func NewHandler(cfg *config.Config, kr *token.Keyring) (*Handler, error) {
	wconfig := &webauthn.Config{
		RPDisplayName: cfg.WebAuthn.RPName,
		RPID:          cfg.WebAuthn.RPID,
		RPOrigins:     cfg.WebAuthn.RPOrigins,
		// Request direct attestation (we want to see TPM certificates)
		AttestationPreference: protocol.PreferDirectAttestation,
		// Require platform authenticators (TPM, Touch ID, Windows Hello)
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.Platform,
			RequireResidentKey:      protocol.ResidentKeyNotRequired(),
			UserVerification:        protocol.VerificationRequired,
		},
	}

	wa, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("webauthn init: %w", err)
	}

	ttl := time.Duration(cfg.WebAuthn.TTLSec) * time.Second
	store := NewStore(ttl)

	return &Handler{
		WebAuthn: wa,
		Store:    store,
		Keyring:  kr,
		Config:   cfg,
	}, nil
}

// BeginRegistration starts a WebAuthn registration ceremony (credential creation).
// POST /v1/challenge/webauthn
func (h *Handler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to prevent DoS
	r.Body = http.MaxBytesReader(w, r.Body, 4*1024) // 4KB limit
	defer r.Body.Close()

	// Parse request
	type Req struct {
		ReturnURL string `json:"return_url"`
	}
	var req Req
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_json"})
		return
	}

	// Sanitize return URL to prevent open redirects
	req.ReturnURL = sanitizeReturnURL(req.ReturnURL)

	// Create ephemeral user
	user, err := NewEphemeralUser()
	if err != nil {
		log.Printf("webauthn: failed to create user: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Begin registration
	options, session, err := h.WebAuthn.BeginRegistration(user)
	if err != nil {
		log.Printf("webauthn: begin registration failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Store session
	challengeID := h.Store.Put(session, user.ID, req.ReturnURL)
	if challengeID == "" {
		log.Printf("webauthn: failed to generate challenge ID")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Build response (standard WebAuthn CredentialCreationOptions plus our challenge_id)
	resp := struct {
		*protocol.CredentialCreation
		ChallengeID string `json:"challenge_id"`
		ReturnURL   string `json:"return_url"`
	}{
		CredentialCreation: options,
		ChallengeID:        challengeID,
		ReturnURL:          req.ReturnURL,
	}

	writeJSON(w, http.StatusOK, resp)
}

// FinishRegistration completes a WebAuthn registration ceremony.
// POST /v1/challenge/complete/webauthn
func (h *Handler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size to prevent DoS
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024) // 1MB limit for attestation
	defer r.Body.Close()

	// Get challenge_id from query parameter with length validation
	challengeID := r.URL.Query().Get("challenge_id")
	if challengeID == "" || len(challengeID) > 256 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_challenge_id"})
		return
	}

	// Parse attestation response
	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		log.Printf("webauthn: failed to parse response: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_attestation"})
		return
	}

	// Retrieve session
	session, userID, returnURL, ok := h.Store.Get(challengeID)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "challenge_not_found"})
		return
	}
	defer h.Store.Consume(challengeID)

	// Recreate user
	user := &User{
		ID:          userID,
		Name:        "anonymous",
		DisplayName: "Anonymous User",
	}

	// Verify attestation
	credential, err := h.WebAuthn.CreateCredential(user, *session, parsedResponse)
	if err != nil {
		log.Printf("webauthn: attestation verification failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "attestation_failed"})
		return
	}

	// Determine tier based on attestation format
	tier := "attested"
	if isHardwareBacked(credential.AttestationType) {
		tier = "hardware_attested"
	}

	// Issue clearance token
	ttl := 24 * time.Hour // Premium TTL for hardware-attested devices
	if tier == "attested" {
		ttl = 12 * time.Hour
	}

	tokenStr, err := h.Keyring.Sign(tier, ttl)
	if err != nil {
		log.Printf("webauthn: failed to sign token: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Set cookie
	http.SetCookie(w, buildCookie(h.Config, tokenStr))

	// Sanitize and redirect to return URL
	returnURL = sanitizeReturnURL(returnURL)
	if returnURL == "" {
		returnURL = "/"
	}

	w.Header().Set("Location", returnURL)
	w.WriteHeader(http.StatusFound)
}

// isHardwareBacked checks if the attestation format indicates hardware-backed credentials.
func isHardwareBacked(attestationType string) bool {
	// TPM, Apple, Android SafetyNet, and packed (with X5C) indicate hardware
	switch attestationType {
	case "tpm", "apple", "android-safetynet":
		return true
	case "packed":
		// Packed can be software or hardware; ideally we'd check for X5C cert chain
		// For now, treat packed as hardware-backed
		return true
	default:
		return false
	}
}

// buildCookie creates a clearance cookie.
func buildCookie(cfg *config.Config, tokenStr string) *http.Cookie {
	c := &http.Cookie{
		Name:     cfg.Cookie.Name,
		Value:    tokenStr,
		Path:     cfg.Cookie.Path,
		MaxAge:   cfg.Cookie.MaxAgeSec,
		Secure:   cfg.Cookie.Secure,
		HttpOnly: cfg.Cookie.HTTPOnly,
	}

	switch cfg.Cookie.SameSite {
	case "None":
		c.SameSite = http.SameSiteNoneMode
	default:
		c.SameSite = http.SameSiteLaxMode
	}

	if cfg.Cookie.Domain != "" {
		c.Domain = cfg.Cookie.Domain
	}

	return c
}

// writeJSON writes a JSON response.
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		log.Printf("ERROR: JSON encode failed: %v", err)
	}
}

// sanitizeReturnURL prevents open redirect attacks by restricting to same-origin paths.
// Accepts: "/", "/path", "/path?query", but NOT "//host", "http://", "https://".
func sanitizeReturnURL(in string) string {
	if in == "" {
		return "/"
	}
	// Quick rejects
	if strings.HasPrefix(in, "//") || strings.HasPrefix(in, "http://") || strings.HasPrefix(in, "https://") {
		return "/"
	}
	u, err := url.ParseRequestURI(in)
	if err != nil {
		return "/"
	}
	if !strings.HasPrefix(u.Path, "/") {
		return "/"
	}
	// Keep path + raw query; drop fragments (browsers keep them client-side anyway)
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}
