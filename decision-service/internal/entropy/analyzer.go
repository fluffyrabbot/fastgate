package entropy

import (
	"math"
)

// Profile represents the complete entropy profile from the client.
type Profile struct {
	Version   string    `json:"version"`
	Timestamp int64     `json:"timestamp"`
	Scores    Scores    `json:"scores"`
	Entropy   Entropy   `json:"entropy"`
	Anomalies Anomalies `json:"anomalies"`
	Signals   Signals   `json:"signals"`
	Fingerprint string  `json:"fingerprint"`
}

// Scores contains bot/human likelihood scores.
type Scores struct {
	Bot        float64 `json:"bot"`
	Human      float64 `json:"human"`
	Confidence float64 `json:"confidence"`
}

// Entropy contains entropy measurements for different signal categories.
type Entropy struct {
	Mouse       float64 `json:"mouse"`
	Timing      float64 `json:"timing"`
	Interaction float64 `json:"interaction"`
}

// Anomalies contains detected anomalies by category.
type Anomalies struct {
	Hardware    []string `json:"hardware"`
	Behavioral  []string `json:"behavioral"`
	Environment []string `json:"environment"`
	Total       int      `json:"total"`
}

// Signals contains all collected signals (sanitized).
type Signals struct {
	Hardware    HardwareSignals    `json:"hardware"`
	Behavioral  BehavioralSignals  `json:"behavioral"`
	Environment EnvironmentSignals `json:"environment"`
}

// HardwareSignals contains hardware-backed signals.
type HardwareSignals struct {
	WebGL struct {
		Vendor     string `json:"vendor"`
		Consistent bool   `json:"consistent"`
	} `json:"webgl"`
	Cores           int     `json:"cores"`
	EventLoopJitter float64 `json:"eventLoopJitter"`
	RAFVariance     float64 `json:"rafVariance"`
	HasTouch        bool    `json:"hasTouch"`
	MaxTouchPoints  int     `json:"maxTouchPoints"`
}

// BehavioralSignals contains behavioral tracking results.
type BehavioralSignals struct {
	MousePathComplexity float64 `json:"mousePathComplexity"`
	KeystrokeTiming     struct {
		Variance int `json:"variance"`
		Count    int `json:"count"`
	} `json:"keystrokeTiming"`
	ScrollPattern struct {
		Smoothness    float64 `json:"smoothness"`
		Count         int     `json:"count"`
		TotalDistance int     `json:"totalDistance"`
	} `json:"scrollPattern"`
	TimeToInteract   int `json:"timeToInteract"`
	ClickPrecision   struct {
		Variance int `json:"variance"`
		Count    int `json:"count"`
		AvgSpeed int `json:"avgSpeed"`
	} `json:"clickPrecision"`
	InteractionCount int `json:"interactionCount"`
}

// EnvironmentSignals contains environment/platform signals.
type EnvironmentSignals struct {
	Screen struct {
		Bucket      string  `json:"bucket"`
		Orientation string  `json:"orientation"`
		PixelRatio  float64 `json:"pixelRatio"`
	} `json:"screen"`
	Timezone struct {
		Offset int `json:"offset"`
	} `json:"timezone"`
	Languages struct {
		Count int `json:"count"`
	} `json:"languages"`
	Features map[string]bool `json:"features"`
	ColorDepth int           `json:"colorDepth"`
	Platform struct {
		CookieEnabled  bool `json:"cookieEnabled"`
		MaxTouchPoints int  `json:"maxTouchPoints"`
	} `json:"platform"`
	Plugins struct {
		Count int `json:"count"`
	} `json:"plugins"`
}

// Analyzer analyzes entropy profiles and produces bot detection scores.
type Analyzer struct {
	// Configuration thresholds
	BotThreshold      float64 // Score above this = likely bot (default 0.7)
	CriticalThreshold float64 // Score above this = definite bot (default 0.9)
	LowEntropyPenalty int     // Score penalty for low entropy (default 20)
	AnomalyPenalty    int     // Score penalty per anomaly (default 10)
}

// NewAnalyzer creates a new entropy analyzer with default thresholds.
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		BotThreshold:      0.7,
		CriticalThreshold: 0.9,
		LowEntropyPenalty: 20,
		AnomalyPenalty:    10,
	}
}

// Analyze evaluates an entropy profile and returns a bot assessment.
func (a *Analyzer) Analyze(profile *Profile) *Assessment {
	if profile == nil {
		return &Assessment{
			IsSuspicious: false,
			IsBot:        false,
			BotScore:     0,
			Confidence:   0,
			Reasons:      []string{"no_entropy_data"},
		}
	}

	reasons := []string{}
	scorePenalty := 0

	// Check bot score threshold
	if profile.Scores.Bot >= a.CriticalThreshold {
		reasons = append(reasons, "entropy_critical")
		scorePenalty += 50
	} else if profile.Scores.Bot >= a.BotThreshold {
		reasons = append(reasons, "entropy_high")
		scorePenalty += 30
	}

	// Check for critical anomalies (strong bot indicators)
	criticalAnomalies := a.findCriticalAnomalies(profile)
	if len(criticalAnomalies) > 0 {
		reasons = append(reasons, "entropy_critical_anomalies")
		scorePenalty += len(criticalAnomalies) * 15
	}

	// Check for low entropy (bot-like behavior)
	avgEntropy := (profile.Entropy.Mouse + profile.Entropy.Timing + profile.Entropy.Interaction) / 3.0
	if avgEntropy < 1.0 {
		reasons = append(reasons, "entropy_low")
		scorePenalty += a.LowEntropyPenalty
	}

	// Check total anomaly count
	if profile.Anomalies.Total > 5 {
		reasons = append(reasons, "entropy_many_anomalies")
		scorePenalty += (profile.Anomalies.Total - 5) * a.AnomalyPenalty
	}

	// Check for instant interaction (strong bot indicator)
	if profile.Signals.Behavioral.TimeToInteract >= 0 && profile.Signals.Behavioral.TimeToInteract < 100 {
		reasons = append(reasons, "entropy_instant_interaction")
		scorePenalty += 25
	}

	// Check for minimal interaction
	if profile.Signals.Behavioral.InteractionCount < 5 {
		reasons = append(reasons, "entropy_minimal_interaction")
		scorePenalty += 15
	}

	return &Assessment{
		IsSuspicious:     profile.Scores.Bot >= 0.5 || len(criticalAnomalies) > 0,
		IsBot:            profile.Scores.Bot >= a.BotThreshold,
		BotScore:         profile.Scores.Bot,
		Confidence:       profile.Scores.Confidence,
		Reasons:          reasons,
		ScorePenalty:     scorePenalty,
		CriticalAnomalies: criticalAnomalies,
		TotalAnomalies:   profile.Anomalies.Total,
		AvgEntropy:       avgEntropy,
	}
}

// Assessment represents the results of entropy analysis.
type Assessment struct {
	IsSuspicious      bool     // True if bot score >= 0.5 or critical anomalies detected
	IsBot             bool     // True if bot score >= bot threshold
	BotScore          float64  // Bot likelihood (0.0-1.0)
	Confidence        float64  // Confidence in the assessment (0.0-1.0)
	Reasons           []string // Human-readable reasons for the assessment
	ScorePenalty      int      // Suggested score penalty to add to authz score
	CriticalAnomalies []string // Critical anomalies detected
	TotalAnomalies    int      // Total anomaly count
	AvgEntropy        float64  // Average entropy across all categories
}

// findCriticalAnomalies identifies critical anomalies that are strong bot indicators.
func (a *Analyzer) findCriticalAnomalies(profile *Profile) []string {
	criticalList := map[string]bool{
		"headless_swiftshader":      true,
		"headless_ua":               true,
		"phantom_ua":                true,
		"instant_interaction":       true,
		"straight_mouse_path":       true,
		"perfect_clicks":            true,
		"consistent_keystrokes":     true,
		"vendor_platform_mismatch":  true,
		"missing_modern_features":   true,
	}

	var critical []string
	allAnomalies := append(append(profile.Anomalies.Hardware, profile.Anomalies.Behavioral...), profile.Anomalies.Environment...)

	for _, anomaly := range allAnomalies {
		if criticalList[anomaly] {
			critical = append(critical, anomaly)
		}
	}

	return critical
}

// CalculateEntropyScore computes a simple entropy score from an entropy profile.
// Returns 0-100, where higher = more suspicious.
func CalculateEntropyScore(profile *Profile) int {
	if profile == nil {
		return 0
	}

	// Weight bot score heavily (70%)
	botScore := profile.Scores.Bot * 70

	// Weight anomaly count moderately (20%)
	anomalyScore := math.Min(float64(profile.Anomalies.Total)*4, 20)

	// Weight low entropy (10%)
	avgEntropy := (profile.Entropy.Mouse + profile.Entropy.Timing + profile.Entropy.Interaction) / 3.0
	entropyScore := (1.0 - avgEntropy/5.0) * 10

	total := botScore + anomalyScore + entropyScore
	return int(math.Min(total, 100))
}
