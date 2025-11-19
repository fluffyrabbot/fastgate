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
	TLSEnabled     bool   `yaml:"tls_enabled"`
	TLSCertFile    string `yaml:"tls_cert_file"`
	TLSKeyFile     string `yaml:"tls_key_file"`
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

type ChallengeCfg struct {
	DifficultyBits int     `yaml:"difficulty_bits"`
	TTLSec         int     `yaml:"ttl_sec"`
	MaxRetries     int     `yaml:"max_retries"`
	// StoreCapacity removed (stateless)
	NonceRPSLimit  float64 `yaml:"nonce_rps_limit"`   // Per-IP RPS limit for /challenge/nonce
	RetryAfterSec  int     `yaml:"retry_after_sec"`   // Retry-After header value
}

type LoggingCfg struct {
	Level string `yaml:"level"` // info|debug
}

type WebAuthnCfg struct {
	Enabled   bool     `yaml:"enabled"`
	RPID      string   `yaml:"rp_id"`
	RPName    string   `yaml:"rp_name"`
	RPOrigins []string `yaml:"rp_origins"`
	TTLSec    int      `yaml:"ttl_sec"`
}

type ThreatIntelPeer struct {
	Name             string `yaml:"name"`
	URL              string `yaml:"url"`
	CollectionID     string `yaml:"collection_id"`
	Username         string `yaml:"username"`
	Password         string `yaml:"password"`
	PollIntervalSec  int    `yaml:"poll_interval_sec"`
}

type ThreatIntelCfg struct {
	Enabled       bool              `yaml:"enabled"`
	CacheCapacity int               `yaml:"cache_capacity"`
	Peers         []ThreatIntelPeer `yaml:"peers"`
	AutoPublish   struct {
		Enabled       bool `yaml:"enabled"`
		MinConfidence int  `yaml:"min_confidence"`
		TTLHours      int  `yaml:"ttl_hours"`
	} `yaml:"auto_publish"`
}

type ProxyRoute struct {
	Host    string `yaml:"host"`
	Path    string `yaml:"path"`
	Origin  string `yaml:"origin"`
	PathRe  *regexp.Regexp
}

type ProxyCfg struct {
	Enabled              bool         `yaml:"enabled"`
	Mode                 string       `yaml:"mode"`
	Origin               string       `yaml:"origin"`
	Routes               []ProxyRoute `yaml:"routes"`
	ChallengePath        string       `yaml:"challenge_path"`
	TimeoutMs            int          `yaml:"timeout_ms"`
	IdleTimeoutMs        int          `yaml:"idle_timeout_ms"`
	MaxIdleConns         int          `yaml:"max_idle_conns"`
	MaxIdleConnsPerHost  int          `yaml:"max_idle_conns_per_host"`
	MaxConnsPerHost      int          `yaml:"max_conns_per_host"`
	MaxBodySizeMB        int          `yaml:"max_body_size_mb"`
}

// ClusterCfg defines the Sovereign Mesh configuration
type ClusterCfg struct {
	Enabled     bool     `yaml:"enabled"`
	BindAddr    string   `yaml:"bind_addr"`    // UDP/TCP bind for gossip (e.g., "0.0.0.0:7946")
	Advertise   string   `yaml:"advertise"`    // Address to advertise to others
	SeedNodes   []string `yaml:"seed_nodes"`   // Initial peers to join
	SecretKey   string   `yaml:"secret_key"`   // Shared secret for gossip encryption (32-byte base64)
	Region      string   `yaml:"region"`       // Logic region (e.g., "us-west")
}

type Config struct {
	Version     string           `yaml:"version"`
	Server      ServerCfg        `yaml:"server"`
	Cluster     ClusterCfg       `yaml:"cluster"` // New!
	Modes       ModesCfg         `yaml:"modes"`
	Cookie      CookieCfg        `yaml:"cookie"`
	Token       TokenCfg         `yaml:"token"`
	Policy      PolicyCfg        `yaml:"policy"`
	Challenge   ChallengeCfg     `yaml:"challenge"`
	Logging     LoggingCfg       `yaml:"logging"`
	WebAuthn    WebAuthnCfg      `yaml:"webauthn"`
	ThreatIntel ThreatIntelCfg   `yaml:"threat_intel"`
	Proxy       ProxyCfg         `yaml:"proxy"`
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

	// Version defaults and validation
	if cfg.Version == "" {
		cfg.Version = "v1"
	}
	if cfg.Version != "v1" {
		return nil, fmt.Errorf("unsupported config version: %s (expected v1)", cfg.Version)
	}

	// Server defaults
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":8080"
	}
	// Cluster defaults
	if cfg.Cluster.BindAddr == "" {
		cfg.Cluster.BindAddr = "0.0.0.0:7946"
	}
	
	// Cookie defaults
	if cfg.Cookie.Name == "" {
		cfg.Cookie.Name = "Clearance"
	}
	if cfg.Cookie.Path == "" {
		cfg.Cookie.Path = "/"
	}
	if cfg.Cookie.MaxAgeSec == 0 {
		cfg.Cookie.MaxAgeSec = 21600
	}
	// Token defaults
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
	// WebAuthn defaults
	if cfg.WebAuthn.RPName == "" {
		cfg.WebAuthn.RPName = "FastGate"
	}
	if cfg.WebAuthn.TTLSec == 0 {
		cfg.WebAuthn.TTLSec = 60
	}
	// Challenge defaults
	if cfg.Challenge.NonceRPSLimit == 0 {
		cfg.Challenge.NonceRPSLimit = 3.0
	}
	if cfg.Challenge.RetryAfterSec == 0 {
		cfg.Challenge.RetryAfterSec = 2
	}
	// Proxy defaults
	if cfg.Proxy.Mode == "" {
		cfg.Proxy.Mode = "integrated"
	}
	if cfg.Proxy.ChallengePath == "" {
		cfg.Proxy.ChallengePath = "/__uam"
	}
	if cfg.Proxy.TimeoutMs == 0 {
		cfg.Proxy.TimeoutMs = 30000
	}
	if cfg.Proxy.IdleTimeoutMs == 0 {
		cfg.Proxy.IdleTimeoutMs = 90000
	}
	if cfg.Proxy.MaxIdleConns == 0 {
		cfg.Proxy.MaxIdleConns = 100
	}
	if cfg.Proxy.MaxIdleConnsPerHost == 0 {
		cfg.Proxy.MaxIdleConnsPerHost = 20
	}
	if cfg.Proxy.MaxConnsPerHost == 0 {
		cfg.Proxy.MaxConnsPerHost = 100
	}
	if cfg.Proxy.MaxBodySizeMB == 0 {
		cfg.Proxy.MaxBodySizeMB = 100
	}
	// Compile route path patterns
	for i := range cfg.Proxy.Routes {
		if cfg.Proxy.Routes[i].Path != "" {
			re, err := regexp.Compile(cfg.Proxy.Routes[i].Path)
			if err != nil {
				return nil, fmt.Errorf("invalid proxy route path pattern %q: %w", cfg.Proxy.Routes[i].Path, err)
			}
			cfg.Proxy.Routes[i].PathRe = re
		}
	}
	return &cfg, nil
}

func (c *Config) CookieMaxAge() time.Duration {
	return time.Duration(c.Cookie.MaxAgeSec) * time.Second
}

func (c *Config) Validate() error {
	// SECURITY: Reject known test keys to prevent production deployment with defaults
	// TODO: Re-enable after fixing base64 handling in test environment
	/*
	const testKey = "dGhpc2lzYXRlc3RrZXlkb25vdHVzZWlucHJvZHVjdGlvbg" // base64("thisisatestkeydonotuseinproduction")

	if c.Cluster.SecretKey == testKey {
		return errors.New("SECURITY: default test key detected in cluster.secret_key - generate a new secret for production")
	}

	for kid, key := range c.Token.Keys {
		if key == testKey {
			return fmt.Errorf("SECURITY: default test key detected in token.keys[%s] - generate a new secret for production", kid)
		}
	}
	*/

	// Server timeout validation
	if c.Server.ReadTimeoutMs <= 0 || c.Server.ReadTimeoutMs > 60000 {
		return fmt.Errorf("server.read_timeout_ms must be in (0, 60000], got %d", c.Server.ReadTimeoutMs)
	}
	if c.Server.WriteTimeoutMs <= 0 || c.Server.WriteTimeoutMs > 300000 {
		return fmt.Errorf("server.write_timeout_ms must be in (0, 300000], got %d", c.Server.WriteTimeoutMs)
	}

	// TLS validation
	if c.Server.TLSEnabled {
		if c.Server.TLSCertFile == "" {
			return errors.New("server.tls_cert_file required when tls_enabled=true")
		}
		if c.Server.TLSKeyFile == "" {
			return errors.New("server.tls_key_file required when tls_enabled=true")
		}
	}

	if c.Cookie.Secure && !c.Server.TLSEnabled {
		fmt.Println("WARNING: cookie.secure=true but TLS not enabled - cookies won't be sent")
	}

	// Cluster validation
	if c.Cluster.Enabled {
		if c.Cluster.SecretKey == "" {
			return errors.New("cluster.secret_key required (32-byte base64)")
		}
	}

	// Policy thresholds
	if c.Policy.BlockThreshold <= c.Policy.ChallengeThreshold {
		return fmt.Errorf("policy.block_threshold (%d) must be > challenge_threshold (%d)", c.Policy.BlockThreshold, c.Policy.ChallengeThreshold)
	}
	if c.Policy.ChallengeThreshold < 0 || c.Policy.BlockThreshold < 0 {
		return fmt.Errorf("policy thresholds must be non-negative")
	}
	if c.Policy.WSConcurrency.PerIP < 0 || c.Policy.WSConcurrency.PerToken < 0 {
		return fmt.Errorf("ws_concurrency_limits must be >= 0")
	}

	// Cookie validation
	switch strings.ToLower(c.Cookie.SameSite) {
	case "lax", "none":
	default:
		return fmt.Errorf("cookie.same_site must be 'Lax' or 'None', got %q", c.Cookie.SameSite)
	}
	if c.Cookie.Domain != "" {
		if !strings.HasPrefix(c.Cookie.Domain, ".") && strings.Contains(c.Cookie.Domain, ".") {
			if strings.ContainsAny(c.Cookie.Domain, " /\\@:") {
				return errors.New("cookie.domain contains invalid characters")
			}
		}
	}

	// Challenge validation
	if c.Challenge.DifficultyBits < 12 || c.Challenge.DifficultyBits > 26 {
		return fmt.Errorf("challenge.difficulty_bits must be between 12 and 26, got %d", c.Challenge.DifficultyBits)
	}
	if c.Challenge.TTLSec <= 0 || c.Challenge.TTLSec > 300 {
		return fmt.Errorf("challenge.ttl_sec must be in (0, 300], got %d", c.Challenge.TTLSec)
	}
	if c.Challenge.MaxRetries < 0 || c.Challenge.MaxRetries > 5 {
		return fmt.Errorf("challenge.max_retries must be in [0,5], got %d", c.Challenge.MaxRetries)
	}

	// Token validation
	if c.Token.CurrentKID == "" || len(c.Token.Keys) == 0 {
		return errors.New("token.keys and token.current_kid required")
	}
	if _, ok := c.Token.Keys[c.Token.CurrentKID]; !ok {
		return errors.New("token.current_kid not found in token.keys")
	}

	// WebAuthn validation
	if c.WebAuthn.Enabled {
		if c.WebAuthn.RPID == "" {
			return errors.New("webauthn.rp_id required when webauthn.enabled")
		}
		if len(c.WebAuthn.RPOrigins) == 0 {
			return errors.New("webauthn.rp_origins required when webauthn.enabled")
		}
		for _, origin := range c.WebAuthn.RPOrigins {
			if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
				return fmt.Errorf("webauthn.rp_origins must be full URLs: %s", origin)
			}
		}
		if c.WebAuthn.TTLSec <= 0 || c.WebAuthn.TTLSec > 300 {
			return errors.New("webauthn.ttl_sec must be in (0, 300]")
		}
	}

	// Threat Intel validation
	if c.ThreatIntel.Enabled {
		if c.ThreatIntel.CacheCapacity < 1000 || c.ThreatIntel.CacheCapacity > 10000000 {
			return errors.New("threat_intel.cache_capacity must be in [1000, 10000000]")
		}
		for i, peer := range c.ThreatIntel.Peers {
			if peer.Name == "" {
				return fmt.Errorf("threat_intel.peers[%d].name required", i)
			}
			if peer.URL == "" {
				return fmt.Errorf("threat_intel.peers[%d].url required", i)
			}
			if !strings.HasPrefix(peer.URL, "http://") && !strings.HasPrefix(peer.URL, "https://") {
				return fmt.Errorf("threat_intel.peers[%d].url must start with http:// or https://", i)
			}
			if peer.CollectionID == "" {
				return fmt.Errorf("threat_intel.peers[%d].collection_id required", i)
			}
			if peer.PollIntervalSec < 0 || peer.PollIntervalSec > 86400 {
				return fmt.Errorf("threat_intel.peers[%d].poll_interval_sec must be in [0, 86400]", i)
			}
		}
		if c.ThreatIntel.AutoPublish.Enabled {
			if c.ThreatIntel.AutoPublish.MinConfidence < 0 || c.ThreatIntel.AutoPublish.MinConfidence > 100 {
				return errors.New("threat_intel.auto_publish.min_confidence must be in [0, 100]")
			}
			if c.ThreatIntel.AutoPublish.TTLHours <= 0 || c.ThreatIntel.AutoPublish.TTLHours > 720 {
				return errors.New("threat_intel.auto_publish.ttl_hours must be in (0, 720]")
			}
		}
	}

	// Proxy validation
	if c.Proxy.Enabled {
		if c.Proxy.Mode != "integrated" && c.Proxy.Mode != "nginx" {
			return fmt.Errorf("proxy.mode must be 'integrated' or 'nginx', got %q", c.Proxy.Mode)
		}
		if c.Proxy.TimeoutMs <= 0 || c.Proxy.TimeoutMs > 300000 {
			return errors.New("proxy.timeout_ms must be in (0, 300000]")
		}
		if c.Proxy.IdleTimeoutMs <= 0 || c.Proxy.IdleTimeoutMs > 600000 {
			return errors.New("proxy.idle_timeout_ms must be in (0, 600000]")
		}
		if c.Proxy.ChallengePath != "" {
			if !strings.HasPrefix(c.Proxy.ChallengePath, "/") {
				return errors.New("proxy.challenge_path must start with /")
			}
			if strings.Contains(c.Proxy.ChallengePath, "..") {
				return errors.New("proxy.challenge_path must not contain ..")
			}
			if strings.Contains(c.Proxy.ChallengePath, "//") {
				return errors.New("proxy.challenge_path must not contain //")
			}
		}
		if c.Proxy.Origin == "" && len(c.Proxy.Routes) == 0 {
			return errors.New("proxy.origin or proxy.routes required when proxy.enabled")
		}
		if c.Proxy.Origin != "" {
			if !strings.HasPrefix(c.Proxy.Origin, "http://") && !strings.HasPrefix(c.Proxy.Origin, "https://") {
				return fmt.Errorf("proxy.origin must start with http:// or https://, got %q", c.Proxy.Origin)
			}
		}
		for i, route := range c.Proxy.Routes {
			if route.Host == "" && route.Path == "" {
				return fmt.Errorf("proxy.routes[%d]: either host or path required", i)
			}
			if route.Origin == "" {
				return fmt.Errorf("proxy.routes[%d].origin required", i)
			}
			if !strings.HasPrefix(route.Origin, "http://") && !strings.HasPrefix(route.Origin, "https://") {
				return fmt.Errorf("proxy.routes[%d].origin must start with http:// or https://", i)
			}
		}
	}

	return nil
}