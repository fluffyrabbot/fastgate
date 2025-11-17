# Phase 3: Behavioral Entropy Fingerprinting

**Status**: Proposed
**Priority**: Medium
**Effort**: 3-4 weeks
**Innovation Level**: 🔥🔥🔥 High (Privacy-preserving bot detection)

---

## 1. Overview

### Problem Statement
Current FastGate uses **brittle heuristics** for bot detection:

```go
// decision-service/internal/authz/handler.go:247
func looksHeadless(ua string) bool {
    return strings.Contains(ua, "curl")  // ❌ Trivially bypassable
}
```

**Problems:**
- Bots spoof User-Agent strings (one-line change)
- Binary decision (headless vs not) loses nuance
- No behavioral analysis (can't detect sophisticated bots)
- Privacy violations (User-Agent strings leak device details)

### Solution
Implement **behavioral entropy fingerprinting** that:
1. Measures high-entropy signals (hard to fake)
2. Analyzes browser behavior (mouse, keyboard, timing)
3. Respects privacy (no persistent tracking)
4. Uses statistical models (not simple string matching)

### Key Benefits
- **Higher accuracy**: Detect headless browsers, emulators, automation tools
- **Privacy-first**: No canvas fingerprinting or cross-site tracking
- **Adaptive**: Learns from attack patterns
- **Transparent**: Users can inspect what's being measured

---

## 2. Technical Architecture

### 2.1 Signal Categories

#### **Category A: Hardware Entropy (High Confidence)**
Signals that reveal genuine hardware vs emulators:

```javascript
// challenge-page/entropy/hardware.js

async function gatherHardwareSignals() {
    return {
        // GPU rendering consistency
        webglVendor: detectWebGLVendor(),           // "Apple GPU", "NVIDIA", etc.
        webglRenderer: detectWebGLRenderer(),       // Model name
        webglHashConsistency: await testWebGLHash(), // Render same scene 3x, check hash stability

        // Hardware concurrency
        logicalCores: navigator.hardwareConcurrency || 0,

        // Performance timing (VMs have different patterns)
        eventLoopJitter: await measureEventLoopJitter(100),  // Sample 100ms
        rafTimingVariance: await measureRAFVariance(60),     // 60 frames

        // Touch/pointer capabilities
        maxTouchPoints: navigator.maxTouchPoints || 0,
        pointerTypes: getPointerTypes(),  // ["touch", "mouse", "pen"]

        // Media device access (bots rarely have cameras/mics)
        hasMediaDevices: !!navigator.mediaDevices,
        deviceCount: await estimateDeviceCount(),  // Doesn't request permissions
    };
}
```

#### **Category B: Behavioral Signals (Medium Confidence)**
Patterns that distinguish humans from bots:

```javascript
// challenge-page/entropy/behavior.js

function gatherBehavioralSignals() {
    return {
        // Mouse movement analysis
        mousePath: analyzeMousePath(mouseEvents),     // Bezier curve complexity
        mouseAcceleration: calculateAcceleration(),   // Humans accelerate/decelerate
        mouseIdleTime: calculateIdleTime(),           // Time between movements

        // Keyboard dynamics
        keystrokeTiming: analyzeKeystrokes(),         // Dwell time, flight time
        backspaceRate: calculateBackspaceRate(),      // Humans make mistakes

        // Scroll behavior
        scrollPattern: analyzeScrollPattern(),        // Smooth vs jumpy
        scrollAcceleration: measureScrollAccel(),     // Humans ease in/out

        // Navigation timing
        pageLoadToAction: Date.now() - performance.timing.loadEventEnd,
        timeToInteract: measureTimeToFirstInteraction(),
    };
}
```

#### **Category C: Browser Environment (Low Confidence)**
Context clues about the environment:

```javascript
// challenge-page/entropy/environment.js

function gatherEnvironmentSignals() {
    return {
        // Window dimensions (real users don't use 800x600)
        screenWidth: screen.width,
        screenHeight: screen.height,
        windowWidth: window.innerWidth,
        windowHeight: window.innerHeight,
        screenOrientaton: screen.orientation?.type || "unknown",

        // Privacy-preserving bucketing
        screenSizeBucket: bucketScreenSize(screen.width, screen.height),

        // Timezone & language (already collected, now used differently)
        timezoneOffset: new Date().getTimezoneOffset(),
        languages: navigator.languages || [navigator.language],

        // Browser features
        hasLocalStorage: typeof localStorage !== "undefined",
        hasSessionStorage: typeof sessionStorage !== "undefined",
        hasIndexedDB: typeof indexedDB !== "undefined",
        hasServiceWorker: "serviceWorker" in navigator,

        // Permissions API (check without requesting)
        permissionsSupport: "permissions" in navigator,
    };
}
```

### 2.2 Entropy Calculation

**Shannon Entropy Formula:**
```
H(X) = -Σ p(x) * log₂(p(x))
```

**Implementation:**
```javascript
// challenge-page/entropy/calculator.js

function calculateEntropy(signals) {
    // Flatten nested objects into key-value pairs
    const features = flattenSignals(signals);

    // Calculate entropy for each feature
    let totalEntropy = 0;
    for (const [key, value] of Object.entries(features)) {
        const valueStr = String(value);
        const probability = estimateProbability(key, valueStr);

        if (probability > 0) {
            totalEntropy += -probability * Math.log2(probability);
        }
    }

    return {
        totalBits: totalEntropy,
        normalized: totalEntropy / Object.keys(features).length,
        features: features
    };
}

// Estimate probability based on known distributions
function estimateProbability(featureName, value) {
    // For MVP, use empirical distributions from training data
    // Future: Real-time distribution learning

    const distributions = {
        "logicalCores": {
            "2": 0.05,
            "4": 0.25,
            "8": 0.45,
            "16": 0.20,
            "default": 0.05
        },
        "screenSizeBucket": {
            "mobile": 0.40,
            "laptop": 0.45,
            "desktop": 0.10,
            "other": 0.05
        },
        // ... more distributions
    };

    if (distributions[featureName]) {
        return distributions[featureName][value] || distributions[featureName]["default"];
    }

    return 0.5;  // Unknown features get neutral probability
}
```

### 2.3 Anomaly Detection

**Approach**: Use statistical outlier detection instead of rigid rules.

```javascript
// challenge-page/entropy/detector.js

function detectAnomalies(signals) {
    const anomalies = [];

    // Check for impossible combinations
    if (signals.hardware.maxTouchPoints > 0 &&
        signals.environment.screenWidth > 1920) {
        anomalies.push({
            type: "impossible_combination",
            reason: "Touch device with >1920px width is rare",
            severity: 0.7
        });
    }

    // Check for automation signatures
    if (signals.behavior.mousePath.straightLineRatio > 0.9) {
        anomalies.push({
            type: "automation_pattern",
            reason: "Mouse moves in straight lines (bot-like)",
            severity: 0.8
        });
    }

    // Check for missing expected signals
    if (!signals.hardware.webglVendor && signals.environment.hasIndexedDB) {
        anomalies.push({
            type: "missing_signal",
            reason: "Modern browser without WebGL is suspicious",
            severity: 0.6
        });
    }

    // Check for headless browser signatures
    if (detectHeadlessChrome(signals)) {
        anomalies.push({
            type: "headless_detected",
            reason: "Chrome headless signatures present",
            severity: 0.95
        });
    }

    return anomalies;
}

function detectHeadlessChrome(signals) {
    // Headless Chrome has specific WebGL renderer strings
    const headlessRenderers = [
        "SwiftShader",
        "Mesa OffScreen",
        "ANGLE (Google, Vulkan 1.1.0 (SwiftShader",
    ];

    return headlessRenderers.some(pattern =>
        signals.hardware.webglRenderer?.includes(pattern)
    );
}
```

### 2.4 Backend Scoring Engine

```go
// decision-service/internal/entropy/analyzer.go
package entropy

import (
    "encoding/json"
    "math"
)

type Signals struct {
    Hardware    HardwareSignals    `json:"hardware"`
    Behavior    BehaviorSignals    `json:"behavior"`
    Environment EnvironmentSignals `json:"environment"`
}

type HardwareSignals struct {
    WebGLVendor       string  `json:"webglVendor"`
    WebGLRenderer     string  `json:"webglRenderer"`
    LogicalCores      int     `json:"logicalCores"`
    EventLoopJitter   float64 `json:"eventLoopJitter"`
    MaxTouchPoints    int     `json:"maxTouchPoints"`
}

type BehaviorSignals struct {
    MousePathComplexity  float64 `json:"mousePathComplexity"`
    MouseAcceleration    float64 `json:"mouseAcceleration"`
    KeystrokeTiming      float64 `json:"keystrokeTiming"`
    ScrollPattern        string  `json:"scrollPattern"`
    TimeToInteract       int     `json:"timeToInteract"`
}

type EnvironmentSignals struct {
    ScreenWidth      int      `json:"screenWidth"`
    ScreenHeight     int      `json:"screenHeight"`
    TimezoneOffset   int      `json:"timezoneOffset"`
    Languages        []string `json:"languages"`
    HasServiceWorker bool     `json:"hasServiceWorker"`
}

type Score struct {
    EntropyBits     float64   `json:"entropy_bits"`
    BotLikelihood   float64   `json:"bot_likelihood"`   // 0.0-1.0
    Anomalies       []Anomaly `json:"anomalies"`
    DeviceClass     string    `json:"device_class"`
    Recommendation  string    `json:"recommendation"`  // "allow", "challenge", "block"
}

type Anomaly struct {
    Type     string  `json:"type"`
    Severity float64 `json:"severity"`
    Reason   string  `json:"reason"`
}

type Analyzer struct {
    // Pre-trained models or heuristics
}

func NewAnalyzer() *Analyzer {
    return &Analyzer{}
}

func (a *Analyzer) Analyze(signalsJSON []byte) (*Score, error) {
    var signals Signals
    if err := json.Unmarshal(signalsJSON, &signals); err != nil {
        return nil, err
    }

    score := &Score{
        Anomalies: make([]Anomaly, 0),
    }

    // Calculate entropy
    score.EntropyBits = a.calculateEntropy(signals)

    // Detect anomalies
    score.Anomalies = a.detectAnomalies(signals)

    // Calculate bot likelihood (weighted sum of anomalies)
    totalSeverity := 0.0
    for _, anomaly := range score.Anomalies {
        totalSeverity += anomaly.Severity
    }
    score.BotLikelihood = math.Min(totalSeverity, 1.0)

    // Classify device
    score.DeviceClass = a.classifyDevice(signals)

    // Make recommendation
    score.Recommendation = a.recommend(score)

    return score, nil
}

func (a *Analyzer) calculateEntropy(signals Signals) float64 {
    // Simplified Shannon entropy calculation
    entropy := 0.0

    // WebGL vendor entropy (few vendors = low entropy)
    vendorEntropy := a.categoricalEntropy(signals.Hardware.WebGLVendor, map[string]float64{
        "NVIDIA":    0.30,
        "AMD":       0.15,
        "Intel":     0.25,
        "Apple":     0.20,
        "SwiftShader": 0.05,  // Headless
        "other":     0.05,
    })
    entropy += vendorEntropy

    // Logical cores entropy
    coresEntropy := a.categoricalEntropy(string(signals.Hardware.LogicalCores), map[string]float64{
        "2":  0.05,
        "4":  0.25,
        "8":  0.45,
        "16": 0.20,
        "other": 0.05,
    })
    entropy += coresEntropy

    // Mouse behavior entropy (high variance = high entropy = likely human)
    if signals.Behavior.MousePathComplexity > 0 {
        // Normalize to 0-1, then treat as probability
        mouseEntropy := -signals.Behavior.MousePathComplexity * math.Log2(signals.Behavior.MousePathComplexity)
        entropy += mouseEntropy
    }

    return entropy
}

func (a *Analyzer) categoricalEntropy(value string, distribution map[string]float64) float64 {
    prob, ok := distribution[value]
    if !ok {
        prob = distribution["other"]
    }

    if prob <= 0 {
        return 0
    }

    return -prob * math.Log2(prob)
}

func (a *Analyzer) detectAnomalies(signals Signals) []Anomaly {
    anomalies := make([]Anomaly, 0)

    // Headless Chrome detection
    headlessRenderers := []string{"SwiftShader", "Mesa OffScreen", "ANGLE"}
    for _, pattern := range headlessRenderers {
        if contains(signals.Hardware.WebGLRenderer, pattern) {
            anomalies = append(anomalies, Anomaly{
                Type:     "headless_chrome",
                Severity: 0.95,
                Reason:   "WebGL renderer indicates headless browser",
            })
            break
        }
    }

    // Automation signature (perfect mouse movements)
    if signals.Behavior.MousePathComplexity < 0.1 {
        anomalies = append(anomalies, Anomaly{
            Type:     "automation",
            Severity: 0.8,
            Reason:   "Mouse movements too perfect (bot-like)",
        })
    }

    // No interaction (suspicious for challenge page)
    if signals.Behavior.TimeToInteract > 30000 {  // 30 seconds
        anomalies = append(anomalies, Anomaly{
            Type:     "delayed_interaction",
            Severity: 0.6,
            Reason:   "Unusual delay before interaction",
        })
    }

    // Impossible hardware combo
    if signals.Hardware.MaxTouchPoints > 10 && signals.Environment.ScreenWidth > 2560 {
        anomalies = append(anomalies, Anomaly{
            Type:     "impossible_hardware",
            Severity: 0.7,
            Reason:   "Touch device with desktop resolution",
        })
    }

    return anomalies
}

func (a *Analyzer) classifyDevice(signals Signals) string {
    if signals.Hardware.MaxTouchPoints > 0 && signals.Environment.ScreenWidth < 768 {
        return "mobile"
    }
    if signals.Hardware.MaxTouchPoints > 0 && signals.Environment.ScreenWidth < 1366 {
        return "tablet"
    }
    if signals.Environment.ScreenWidth >= 1920 {
        return "desktop"
    }
    return "laptop"
}

func (a *Analyzer) recommend(score *Score) string {
    if score.BotLikelihood >= 0.8 {
        return "block"
    }
    if score.BotLikelihood >= 0.5 {
        return "challenge"
    }
    return "allow"
}

func contains(s, substr string) bool {
    return len(s) >= len(substr) && s[:len(substr)] == substr
}
```

---

## 3. Implementation Phases

### Phase 3.1: Client-Side Signal Collection (Week 1)

**Files to create:**
- `challenge-page/entropy/hardware.js`
- `challenge-page/entropy/behavior.js`
- `challenge-page/entropy/environment.js`
- `challenge-page/entropy/calculator.js`

**Task 1: Hardware signals**
```javascript
// challenge-page/entropy/hardware.js

export async function gatherHardwareSignals() {
    return {
        webglVendor: getWebGLVendor(),
        webglRenderer: getWebGLRenderer(),
        webglHashConsistency: await testWebGLConsistency(),
        logicalCores: navigator.hardwareConcurrency || 0,
        eventLoopJitter: await measureEventLoopJitter(),
        rafVariance: await measureRAFVariance(),
        maxTouchPoints: navigator.maxTouchPoints || 0,
        pointerTypes: detectPointerTypes(),
        hasMediaDevices: !!navigator.mediaDevices,
    };
}

function getWebGLVendor() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'none';

    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (!debugInfo) return 'unknown';

    return gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
}

function getWebGLRenderer() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return 'none';

    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (!debugInfo) return 'unknown';

    return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
}

async function testWebGLConsistency() {
    // Render same scene 3 times, check if hash is consistent
    // Software renderers (headless) may have non-deterministic results

    const hashes = [];
    for (let i = 0; i < 3; i++) {
        const hash = await renderAndHashWebGL();
        hashes.push(hash);
        await sleep(10);  // Small delay
    }

    const allSame = hashes.every(h => h === hashes[0]);
    return allSame ? 1.0 : 0.0;
}

async function renderAndHashWebGL() {
    const canvas = document.createElement('canvas');
    canvas.width = 256;
    canvas.height = 256;
    const gl = canvas.getContext('webgl');

    if (!gl) return '0';

    // Simple triangle render
    gl.clearColor(0.0, 0.0, 0.0, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT);

    // Get pixel data and hash
    const pixels = new Uint8Array(256 * 256 * 4);
    gl.readPixels(0, 0, 256, 256, gl.RGBA, gl.UNSIGNED_BYTE, pixels);

    return simpleHash(pixels);
}

function simpleHash(data) {
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
        hash = ((hash << 5) - hash) + data[i];
        hash |= 0;
    }
    return hash.toString(16);
}

async function measureEventLoopJitter() {
    const samples = [];
    const targetDelay = 10;  // ms

    for (let i = 0; i < 20; i++) {
        const start = performance.now();
        await sleep(targetDelay);
        const actual = performance.now() - start;
        samples.push(Math.abs(actual - targetDelay));
    }

    // Calculate variance (VMs have higher jitter)
    const mean = samples.reduce((a, b) => a + b) / samples.length;
    const variance = samples.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / samples.length;

    return variance;
}

async function measureRAFVariance() {
    // Measure requestAnimationFrame timing consistency
    const frameTimes = [];
    let lastTime = performance.now();

    return new Promise((resolve) => {
        let frames = 0;
        const maxFrames = 60;

        function measureFrame(timestamp) {
            const delta = timestamp - lastTime;
            frameTimes.push(delta);
            lastTime = timestamp;
            frames++;

            if (frames < maxFrames) {
                requestAnimationFrame(measureFrame);
            } else {
                // Calculate variance
                const mean = frameTimes.reduce((a, b) => a + b) / frameTimes.length;
                const variance = frameTimes.reduce((sum, val) =>
                    sum + Math.pow(val - mean, 2), 0) / frameTimes.length;
                resolve(variance);
            }
        }

        requestAnimationFrame(measureFrame);
    });
}

function detectPointerTypes() {
    const types = [];

    if (window.PointerEvent) {
        // Modern pointer events
        if (matchMedia('(pointer: coarse)').matches) types.push('touch');
        if (matchMedia('(pointer: fine)').matches) types.push('mouse');
    } else {
        // Fallback
        if ('ontouchstart' in window) types.push('touch');
        if (navigator.maxTouchPoints === 0) types.push('mouse');
    }

    return types;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
```

**Task 2: Behavior tracking**
```javascript
// challenge-page/entropy/behavior.js

export class BehaviorTracker {
    constructor() {
        this.mouseEvents = [];
        this.keyEvents = [];
        this.scrollEvents = [];
        this.startTime = Date.now();
        this.firstInteraction = null;

        this.attachListeners();
    }

    attachListeners() {
        document.addEventListener('mousemove', this.onMouseMove.bind(this), { passive: true });
        document.addEventListener('keydown', this.onKeyDown.bind(this), { passive: true });
        document.addEventListener('keyup', this.onKeyUp.bind(this), { passive: true });
        document.addEventListener('scroll', this.onScroll.bind(this), { passive: true });
        document.addEventListener('click', this.onFirstInteraction.bind(this), { once: true });
    }

    onMouseMove(e) {
        this.mouseEvents.push({
            x: e.clientX,
            y: e.clientY,
            t: Date.now()
        });

        // Keep last 100 events only
        if (this.mouseEvents.length > 100) {
            this.mouseEvents.shift();
        }

        if (!this.firstInteraction) {
            this.firstInteraction = Date.now();
        }
    }

    onKeyDown(e) {
        this.keyEvents.push({
            type: 'down',
            key: e.key,
            t: Date.now()
        });
    }

    onKeyUp(e) {
        this.keyEvents.push({
            type: 'up',
            key: e.key,
            t: Date.now()
        });
    }

    onScroll(e) {
        this.scrollEvents.push({
            y: window.scrollY,
            t: Date.now()
        });

        if (this.scrollEvents.length > 50) {
            this.scrollEvents.shift();
        }
    }

    onFirstInteraction() {
        this.firstInteraction = Date.now();
    }

    analyze() {
        return {
            mousePathComplexity: this.analyzeMousePath(),
            mouseAcceleration: this.calculateMouseAcceleration(),
            mouseIdleTime: this.calculateMouseIdleTime(),
            keystrokeTiming: this.analyzeKeystrokes(),
            scrollPattern: this.analyzeScrollPattern(),
            timeToInteract: this.firstInteraction ? (this.firstInteraction - this.startTime) : -1,
        };
    }

    analyzeMousePath() {
        if (this.mouseEvents.length < 10) return 0;

        // Calculate path complexity (deviation from straight line)
        let totalDistance = 0;
        let straightDistance = 0;

        for (let i = 1; i < this.mouseEvents.length; i++) {
            const prev = this.mouseEvents[i - 1];
            const curr = this.mouseEvents[i];

            const dx = curr.x - prev.x;
            const dy = curr.y - prev.y;
            totalDistance += Math.sqrt(dx * dx + dy * dy);
        }

        if (this.mouseEvents.length > 0) {
            const first = this.mouseEvents[0];
            const last = this.mouseEvents[this.mouseEvents.length - 1];
            const dx = last.x - first.x;
            const dy = last.y - first.y;
            straightDistance = Math.sqrt(dx * dx + dy * dy);
        }

        if (straightDistance === 0) return 0;

        // Complexity = how much longer actual path is vs straight line
        // Human paths are ~1.2-1.5x longer, bot paths are ~1.0-1.1x
        return totalDistance / straightDistance;
    }

    calculateMouseAcceleration() {
        if (this.mouseEvents.length < 3) return 0;

        const accelerations = [];

        for (let i = 2; i < this.mouseEvents.length; i++) {
            const p0 = this.mouseEvents[i - 2];
            const p1 = this.mouseEvents[i - 1];
            const p2 = this.mouseEvents[i];

            const v1 = {
                x: (p1.x - p0.x) / (p1.t - p0.t),
                y: (p1.y - p0.y) / (p1.t - p0.t)
            };

            const v2 = {
                x: (p2.x - p1.x) / (p2.t - p1.t),
                y: (p2.y - p1.y) / (p2.t - p1.t)
            };

            const accel = Math.sqrt(
                Math.pow(v2.x - v1.x, 2) + Math.pow(v2.y - v1.y, 2)
            );

            accelerations.push(accel);
        }

        // Return variance (humans have non-uniform acceleration)
        const mean = accelerations.reduce((a, b) => a + b, 0) / accelerations.length;
        const variance = accelerations.reduce((sum, val) =>
            sum + Math.pow(val - mean, 2), 0) / accelerations.length;

        return variance;
    }

    calculateMouseIdleTime() {
        if (this.mouseEvents.length < 2) return 0;

        const last = this.mouseEvents[this.mouseEvents.length - 1];
        return Date.now() - last.t;
    }

    analyzeKeystrokes() {
        if (this.keyEvents.length < 4) return 0;

        // Calculate dwell time (down → up for same key)
        const dwellTimes = [];

        for (let i = 0; i < this.keyEvents.length - 1; i++) {
            const curr = this.keyEvents[i];
            const next = this.keyEvents[i + 1];

            if (curr.type === 'down' && next.type === 'up' && curr.key === next.key) {
                dwellTimes.push(next.t - curr.t);
            }
        }

        if (dwellTimes.length === 0) return 0;

        // Return variance (humans have non-uniform typing rhythm)
        const mean = dwellTimes.reduce((a, b) => a + b, 0) / dwellTimes.length;
        const variance = dwellTimes.reduce((sum, val) =>
            sum + Math.pow(val - mean, 2), 0) / dwellTimes.length;

        return variance;
    }

    analyzeScrollPattern() {
        if (this.scrollEvents.length < 5) return 'none';

        // Check if scrolling is smooth or jumpy
        const deltas = [];
        for (let i = 1; i < this.scrollEvents.length; i++) {
            deltas.push(this.scrollEvents[i].y - this.scrollEvents[i - 1].y);
        }

        const avgDelta = deltas.reduce((a, b) => a + Math.abs(b), 0) / deltas.length;

        if (avgDelta < 5) return 'smooth';
        if (avgDelta > 100) return 'jumpy';
        return 'normal';
    }
}
```

### Phase 3.2: Backend Analyzer (Week 2)

See section 2.4 for complete implementation.

**Additional task: Integration endpoint**
```go
// decision-service/cmd/fastgate/main.go (add endpoint)

mux.Handle("/v1/challenge/analyze", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
        return
    }

    body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024))
    if err != nil {
        http.Error(w, "request too large", http.StatusBadRequest)
        return
    }

    analyzer := entropy.NewAnalyzer()
    score, err := analyzer.Analyze(body)
    if err != nil {
        http.Error(w, "analysis failed", http.StatusBadRequest)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(score)
}))
```

### Phase 3.3: Integration with Challenge Flow (Week 3)

**Modify challenge completion to include entropy analysis:**
```javascript
// challenge-page/app.js (modify submitAttestation)

async function submitPoWWithEntropy(challengeId, nonce, solution, returnUrl) {
    // Gather all signals
    const hardware = await gatherHardwareSignals();
    const behavior = behaviorTracker.analyze();
    const environment = gatherEnvironmentSignals();

    const signals = { hardware, behavior, environment };

    // Submit both PoW solution and entropy signals
    const res = await fetch('/v1/challenge/complete', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            challenge_id: challengeId,
            nonce: nonce,
            solution: solution,
            return_url: returnUrl,
            entropy_signals: signals  // NEW
        })
    });

    if (res.ok || res.status === 302) {
        window.location.replace(returnUrl);
    } else {
        setMsg('Verification failed. <a href="' + returnUrl + '">Try again</a>.');
    }
}
```

**Backend: Modify completion handler**
```go
// decision-service/cmd/fastgate/main.go (modify /v1/challenge/complete)

type CompleteRequest struct {
    ChallengeID    string                 `json:"challenge_id"`
    Nonce          string                 `json:"nonce"`
    Solution       uint32                 `json:"solution"`
    ReturnURL      string                 `json:"return_url"`
    EntropySignals json.RawMessage        `json:"entropy_signals"`  // NEW
}

// In handler:
var req CompleteRequest
json.NewDecoder(r.Body).Decode(&req)

// Validate PoW
ok, reason, _ := chStore.TrySolve(req.ChallengeID, req.Nonce, req.Solution)
if !ok {
    // Reject
}

// NEW: Analyze entropy
var entropyScore *entropy.Score
if len(req.EntropySignals) > 0 {
    analyzer := entropy.NewAnalyzer()
    entropyScore, _ = analyzer.Analyze(req.EntropySignals)

    // If high bot likelihood, reject even with valid PoW
    if entropyScore.BotLikelihood > 0.9 {
        http.Error(w, "automation detected", http.StatusForbidden)
        return
    }
}

// Issue tiered clearance based on entropy
tier := "low"
if entropyScore != nil && entropyScore.BotLikelihood < 0.2 {
    tier = "verified_human"  // Premium tier
}

tokenStr, _ := kr.Sign(tier, cfg.CookieMaxAge())
http.SetCookie(w, buildCookie(cfg, tokenStr))
```

### Phase 3.4: Privacy Protections (Week 4)

**Task: Anonymize signals before logging**
```go
// decision-service/internal/entropy/privacy.go
package entropy

func (s *Signals) Anonymize() *Signals {
    anon := *s

    // Bucket screen resolution
    anon.Environment.ScreenWidth = bucketDimension(s.Environment.ScreenWidth, 100)
    anon.Environment.ScreenHeight = bucketDimension(s.Environment.ScreenHeight, 100)

    // Remove exact language lists (keep count only)
    anon.Environment.Languages = []string{fmt.Sprintf("%d languages", len(s.Environment.Languages))}

    // Generalize WebGL renderer (remove model numbers)
    anon.Hardware.WebGLRenderer = generalizeRenderer(s.Hardware.WebGLRenderer)

    return &anon
}

func bucketDimension(value, bucketSize int) int {
    return (value / bucketSize) * bucketSize
}

func generalizeRenderer(renderer string) string {
    // "NVIDIA GeForce RTX 3080" → "NVIDIA GeForce RTX"
    // "Apple M1 Pro" → "Apple M1"

    prefixes := []string{"NVIDIA", "AMD", "Intel", "Apple", "Mali"}
    for _, prefix := range prefixes {
        if strings.HasPrefix(renderer, prefix) {
            parts := strings.Fields(renderer)
            if len(parts) >= 2 {
                return strings.Join(parts[:2], " ")
            }
            return prefix
        }
    }

    return "Generic"
}
```

---

## 4. Configuration

```yaml
# config.example.yaml
entropy:
  enabled: true

  # Scoring thresholds
  thresholds:
    bot_likelihood_block: 0.90     # >90% bot = block
    bot_likelihood_challenge: 0.50  # >50% bot = challenge

  # Signal collection (opt-in for privacy)
  collect_signals:
    hardware: true
    behavior: true
    environment: true

  # Privacy controls
  privacy:
    anonymize_logs: true
    retain_signals_hours: 1  # Delete after 1 hour

token:
  tier_ttl:
    low: 21600              # 6 hours
    verified_human: 86400   # 24 hours (NEW)
```

---

## 5. Testing Plan

```javascript
// challenge-page/test/entropy.test.js

describe('Behavioral Entropy', () => {
    it('detects headless Chrome', async () => {
        const signals = await gatherHardwareSignals();

        // Simulate headless Chrome
        signals.webglRenderer = 'ANGLE (Google, Vulkan 1.1.0 (SwiftShader';

        const score = await analyzeSignals(signals);
        expect(score.anomalies).toContainEqual(
            expect.objectContaining({ type: 'headless_chrome' })
        );
    });

    it('distinguishes human from bot mouse movements', () => {
        // Bot: straight line
        const botEvents = [
            { x: 0, y: 0, t: 0 },
            { x: 100, y: 100, t: 100 },
            { x: 200, y: 200, t: 200 }
        ];

        const tracker = new BehaviorTracker();
        tracker.mouseEvents = botEvents;
        const analysis = tracker.analyze();

        expect(analysis.mousePathComplexity).toBeLessThan(1.1);  // Nearly straight

        // Human: curved path
        const humanEvents = [
            { x: 0, y: 0, t: 0 },
            { x: 50, y: 70, t: 50 },
            { x: 120, y: 110, t: 100 },
            { x: 200, y: 200, t: 200 }
        ];

        tracker.mouseEvents = humanEvents;
        const humanAnalysis = tracker.analyze();

        expect(humanAnalysis.mousePathComplexity).toBeGreaterThan(1.2);  // Curved
    });
});
```

---

## 6. Success Definition

**Innovation Score: 8/10**
- Privacy-preserving (no canvas fingerprinting)
- Statistical approach (not brittle rules)
- Transparent (users can inspect signals)
- Adaptive (learns from patterns)

**Accuracy Targets:**
- True Positive Rate (detect bots): >90%
- False Positive Rate (block humans): <5%
- Headless Chrome detection: >95%

**Next Steps:**
After Phase 3, proceed to:
- Phase 4: Zero-Knowledge Proof Challenges
- Phase 5: Edge-Distributed Challenge Mesh
