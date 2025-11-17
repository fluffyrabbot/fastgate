package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerCfg struct {
	Listen         string `yaml:"listen"`
	ReadTimeoutMs  int    `yaml:"read_timeout_ms"`
	WriteTimeoutMs int    `yaml:"write_timeout_ms"`
}

type ModesCfg struct {
	Enforce     bool `yaml:"enforce"`
	FailOpen    bool `yaml:"fail_open"`
	UnderAttack bool `yaml:"under_attack"`
}

type CookieCfg struct {
	Name      string `yaml:"name"`
	Domain    string `yaml:"domain"`
	Path      string `yaml:"path"`
	MaxAgeSec int    `yaml:"max_age_sec"`
	SameSite  string `yaml:"same_site"` // Lax | None
	Secure    bool   `yaml:"secure"`
	HTTPOnly  bool   `yaml:"http_only"`
}

type TokenCfg struct {
	Alg        string            `yaml:"alg"`
	Keys       map[string]string `yaml:"keys"`
	CurrentKID string            `yaml:"current_kid"`
	Issuer     string            `yaml:"issuer"`
	SkewSec    int               `yaml:"skew_sec"`
}

type PathRule struct {
	Pattern string `yaml:"pattern"`
	Base    int    `yaml:"base"`
	Re      *regexp.Regexp
}

type PolicyCfg struct {
	ChallengeThreshold int        `yaml:"challenge_threshold"`
	BlockThreshold     int        `yaml:"block_threshold"`
	Paths              []PathRule `yaml:"paths"`
	IPRPSThreshold     int        `yaml:"ip_rps_threshold"`
	TokenRPSThreshold  int        `yaml:"token_rps_threshold"`
	WSConcurrency      struct {
		PerIP    int `yaml:"per_ip"`
		PerToken int `yaml:"per_token"`
	} `yaml:"ws_concurrency_limits"`
}

type RateStoreCfg struct {
	Backend  string `yaml:"backend"`  // memory | redis (future)
	RedisDSN string `yaml:"redis_dsn"`
}

type ChallengeCfg struct {
	DifficultyBits int `yaml:"difficulty_bits"`
	TTLSec         int `yaml:"ttl_sec"`
	MaxRetries     int `yaml:"max_retries"`
}

type LoggingCfg struct {
	Level string `yaml:"level"` // info|debug
}

type AttestationCfg struct {
	Enabled  bool   `yaml:"enabled"`
	Provider string `yaml:"provider"`   // "privpass" (Privacy Pass / PAT-style)
	Header   string `yaml:"header"`     // e.g., "Private-Token" or "Authorization"
	Cookie   string `yaml:"cookie"`     // optional fallback cookie
	Audience string `yaml:"audience"`   // optional hint to redemption
	Issuer   string `yaml:"issuer"`     // optional hint to redemption
	Tier     string `yaml:"tier"`       // resulting clearance tier (default "attested")
	MaxTTLSec int   `yaml:"max_ttl_sec"` // clamp clearance TTL
	Cache struct {
		Capacity int `yaml:"capacity"`
		TTLSec   int `yaml:"ttl_sec"`
	} `yaml:"cache"`
	Redemption struct {
		Endpoint  string `yaml:"endpoint"`   // https://issuer.example/redeem
		TimeoutMs int    `yaml:"timeout_ms"` // default 400ms
	} `yaml:"redemption"`
}

type WebAuthnCfg struct {
	Enabled   bool     `yaml:"enabled"`
	RPID      string   `yaml:"rp_id"`      // e.g., "localhost" or "example.com"
	RPName    string   `yaml:"rp_name"`    // e.g., "FastGate"
	RPOrigins []string `yaml:"rp_origins"` // e.g., ["http://localhost:8088", "https://example.com"]
	TTLSec    int      `yaml:"ttl_sec"`    // challenge TTL (default 60s)
}

type Config struct {
	Server      ServerCfg      `yaml:"server"`
	Modes       ModesCfg       `yaml:"modes"`
	Cookie      CookieCfg      `yaml:"cookie"`
	Token       TokenCfg       `yaml:"token"`
	Policy      PolicyCfg      `yaml:"policy"`
	RateStore   RateStoreCfg   `yaml:"rate_store"`
	Challenge   ChallengeCfg   `yaml:"challenge"`
	Logging     LoggingCfg     `yaml:"logging"`
	Attestation AttestationCfg `yaml:"attestation"`
	WebAuthn    WebAuthnCfg    `yaml:"webauthn"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	// defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	if cfg.Cookie.Name == "" {
		cfg.Cookie.Name = "Clearance"
	}
	if cfg.Cookie.Path == "" {
		cfg.Cookie.Path = "/"
	}
	if cfg.Cookie.MaxAgeSec == 0 {
		cfg.Cookie.MaxAgeSec = 21600
	}
	if cfg.Token.Alg == "" {
		cfg.Token.Alg = "HS256"
	}
	if cfg.Token.Issuer == "" {
		cfg.Token.Issuer = "fastgate"
	}
	if cfg.Token.SkewSec == 0 {
		cfg.Token.SkewSec = 30
	}
	for i := range cfg.Policy.Paths {
		re, err := regexp.Compile(cfg.Policy.Paths[i].Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid path pattern %q: %w", cfg.Policy.Paths[i].Pattern, err)
		}
		cfg.Policy.Paths[i].Re = re
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	// Attestation defaults
	if cfg.Attestation.Header == "" {
		cfg.Attestation.Header = "Private-Token"
	}
	if cfg.Attestation.Tier == "" {
		cfg.Attestation.Tier = "attested"
	}
	if cfg.Attestation.MaxTTLSec == 0 {
		cfg.Attestation.MaxTTLSec = 24 * 3600
	}
	if cfg.Attestation.Cache.Capacity == 0 {
		cfg.Attestation.Cache.Capacity = 100_000
	}
	if cfg.Attestation.Cache.TTLSec == 0 {
		cfg.Attestation.Cache.TTLSec = 3600
	}
	if cfg.Attestation.Redemption.TimeoutMs == 0 {
		cfg.Attestation.Redemption.TimeoutMs = 400
	}
	// WebAuthn defaults
	if cfg.WebAuthn.RPName == "" {
		cfg.WebAuthn.RPName = "FastGate"
	}
	if cfg.WebAuthn.TTLSec == 0 {
		cfg.WebAuthn.TTLSec = 60
	}
	return &cfg, nil
}

func (c *Config) CookieMaxAge() time.Duration {
	return time.Duration(c.Cookie.MaxAgeSec) * time.Second
}

func (c *Config) Validate() error {
	if c.Policy.BlockThreshold <= c.Policy.ChallengeThreshold {
		return errors.New("policy.block_threshold must be > challenge_threshold")
	}
	if c.Policy.ChallengeThreshold < 0 || c.Policy.BlockThreshold < 0 {
		return errors.New("policy thresholds must be non-negative")
	}
	switch strings.ToLower(c.Cookie.SameSite) {
	case "lax", "none":
	default:
		return errors.New("cookie.same_site must be 'Lax' or 'None'")
	}
	if c.Policy.WSConcurrency.PerIP < 0 || c.Policy.WSConcurrency.PerToken < 0 {
		return errors.New("ws_concurrency_limits must be >= 0")
	}
	if c.Challenge.DifficultyBits < 12 || c.Challenge.DifficultyBits > 26 {
		return errors.New("challenge.difficulty_bits must be between 12 and 26")
	}
	if c.Challenge.TTLSec <= 0 || c.Challenge.TTLSec > 300 {
		return errors.New("challenge.ttl_sec must be in (0, 300]")
	}
	if c.Challenge.MaxRetries < 0 || c.Challenge.MaxRetries > 5 {
		return errors.New("challenge.max_retries must be in [0,5]")
	}
	if c.Token.CurrentKID == "" || len(c.Token.Keys) == 0 {
		return errors.New("token.keys and token.current_kid required")
	}
	if _, ok := c.Token.Keys[c.Token.CurrentKID]; !ok {
		return errors.New("token.current_kid not found in token.keys")
	}

	// Attestation validation
	if c.Attestation.Enabled {
		if c.Attestation.Provider != "privpass" {
			return errors.New("attestation.provider must be 'privpass' (for Privacy Pass/PAT-style)")
		}
		if c.Attestation.Redemption.Endpoint == "" {
			return errors.New("attestation.redemption.endpoint required when attestation.enabled")
		}
		if c.Attestation.Header == "" && c.Attestation.Cookie == "" {
			return errors.New("attestation.header or attestation.cookie required")
		}
	}

	return nil
}
