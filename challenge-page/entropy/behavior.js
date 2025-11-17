// behavior.js - Behavioral signal tracking for entropy fingerprinting
// Part of Phase 3: Privacy-preserving bot detection

/**
 * BehaviorTracker class for collecting behavioral signals during challenge interaction.
 * Tracks mouse movements, keyboard patterns, scrolling, and timing.
 */
export class BehaviorTracker {
  constructor() {
    this.mousePoints = [];
    this.keystrokes = [];
    this.scrollEvents = [];
    this.clicks = [];
    this.startTime = Date.now();
    this.firstInteractionTime = null;
    this.isTracking = false;
  }

  /**
   * Starts tracking behavioral signals.
   * Attaches event listeners to capture user interactions.
   */
  start() {
    if (this.isTracking) return;
    this.isTracking = true;
    this.startTime = Date.now();

    // Mouse movement tracking
    document.addEventListener('mousemove', this.handleMouseMove, { passive: true });

    // Keyboard tracking
    document.addEventListener('keydown', this.handleKeyDown, { passive: true });
    document.addEventListener('keyup', this.handleKeyUp, { passive: true });

    // Scroll tracking
    document.addEventListener('scroll', this.handleScroll, { passive: true });

    // Click tracking
    document.addEventListener('click', this.handleClick, { passive: true });

    // Touch tracking (for mobile)
    document.addEventListener('touchstart', this.handleTouch, { passive: true });
    document.addEventListener('touchmove', this.handleTouchMove, { passive: true });
  }

  /**
   * Stops tracking and removes event listeners.
   */
  stop() {
    if (!this.isTracking) return;
    this.isTracking = false;

    document.removeEventListener('mousemove', this.handleMouseMove);
    document.removeEventListener('keydown', this.handleKeyDown);
    document.removeEventListener('keyup', this.handleKeyUp);
    document.removeEventListener('scroll', this.handleScroll);
    document.removeEventListener('click', this.handleClick);
    document.removeEventListener('touchstart', this.handleTouch);
    document.removeEventListener('touchmove', this.handleTouchMove);
  }

  handleMouseMove = (e) => {
    const now = Date.now();
    if (this.firstInteractionTime === null) {
      this.firstInteractionTime = now;
    }

    // Sample mouse path (don't store every point to save memory)
    if (this.mousePoints.length === 0 || now - this.mousePoints[this.mousePoints.length - 1].t > 50) {
      this.mousePoints.push({
        x: e.clientX,
        y: e.clientY,
        t: now
      });

      // Keep only last 100 points
      if (this.mousePoints.length > 100) {
        this.mousePoints.shift();
      }
    }
  };

  handleKeyDown = (e) => {
    const now = Date.now();
    if (this.firstInteractionTime === null) {
      this.firstInteractionTime = now;
    }

    // Track keystroke timing (not the actual keys for privacy)
    this.keystrokes.push({
      type: 'down',
      t: now,
      key: e.key.length === 1 ? 'char' : 'special' // Don't record actual keys
    });

    // Keep only last 50 keystrokes
    if (this.keystrokes.length > 50) {
      this.keystrokes.shift();
    }
  };

  handleKeyUp = (e) => {
    const now = Date.now();

    this.keystrokes.push({
      type: 'up',
      t: now,
      key: e.key.length === 1 ? 'char' : 'special'
    });

    if (this.keystrokes.length > 50) {
      this.keystrokes.shift();
    }
  };

  handleScroll = (e) => {
    const now = Date.now();
    if (this.firstInteractionTime === null) {
      this.firstInteractionTime = now;
    }

    // Sample scroll events
    if (this.scrollEvents.length === 0 || now - this.scrollEvents[this.scrollEvents.length - 1].t > 100) {
      this.scrollEvents.push({
        y: window.scrollY,
        t: now
      });

      // Keep only last 20 scroll events
      if (this.scrollEvents.length > 20) {
        this.scrollEvents.shift();
      }
    }
  };

  handleClick = (e) => {
    const now = Date.now();
    if (this.firstInteractionTime === null) {
      this.firstInteractionTime = now;
    }

    this.clicks.push({
      x: e.clientX,
      y: e.clientY,
      t: now,
      button: e.button
    });

    // Keep only last 20 clicks
    if (this.clicks.length > 20) {
      this.clicks.shift();
    }
  };

  handleTouch = (e) => {
    const now = Date.now();
    if (this.firstInteractionTime === null) {
      this.firstInteractionTime = now;
    }

    if (e.touches.length > 0) {
      this.clicks.push({
        x: e.touches[0].clientX,
        y: e.touches[0].clientY,
        t: now,
        button: -1 // Touch event
      });

      if (this.clicks.length > 20) {
        this.clicks.shift();
      }
    }
  };

  handleTouchMove = (e) => {
    const now = Date.now();

    if (e.touches.length > 0 && (this.mousePoints.length === 0 || now - this.mousePoints[this.mousePoints.length - 1].t > 50)) {
      this.mousePoints.push({
        x: e.touches[0].clientX,
        y: e.touches[0].clientY,
        t: now
      });

      if (this.mousePoints.length > 100) {
        this.mousePoints.shift();
      }
    }
  };

  /**
   * Extracts behavioral signals from tracked data.
   * @returns {Object} Behavioral signals
   */
  getSignals() {
    return {
      mousePathComplexity: this.calculateMousePathComplexity(),
      keystrokeTiming: this.calculateKeystrokeTiming(),
      scrollPattern: this.calculateScrollPattern(),
      timeToInteract: this.calculateTimeToInteract(),
      clickPrecision: this.calculateClickPrecision(),
      interactionCount: this.mousePoints.length + this.keystrokes.length + this.clicks.length,
      timestamp: Date.now()
    };
  }

  /**
   * Calculates mouse path complexity by measuring deviation from straight lines.
   * Bots tend to move in perfectly straight lines or unnaturally smooth curves.
   * @returns {number} Complexity score (0-1, higher is more human)
   */
  calculateMousePathComplexity() {
    if (this.mousePoints.length < 3) {
      return 0; // Not enough data
    }

    let totalDeviation = 0;
    let totalDistance = 0;

    // Measure deviation from straight line between every 3 consecutive points
    for (let i = 0; i < this.mousePoints.length - 2; i++) {
      const p1 = this.mousePoints[i];
      const p2 = this.mousePoints[i + 1];
      const p3 = this.mousePoints[i + 2];

      // Calculate direct distance from p1 to p3
      const directDist = Math.sqrt(Math.pow(p3.x - p1.x, 2) + Math.pow(p3.y - p1.y, 2));

      // Calculate actual path distance (p1 -> p2 -> p3)
      const actualDist = Math.sqrt(Math.pow(p2.x - p1.x, 2) + Math.pow(p2.y - p1.y, 2)) +
                         Math.sqrt(Math.pow(p3.x - p2.x, 2) + Math.pow(p3.y - p2.y, 2));

      if (directDist > 0) {
        totalDeviation += (actualDist - directDist) / directDist;
        totalDistance += directDist;
      }
    }

    if (totalDistance === 0) return 0;

    // Normalize to 0-1 range (typical human complexity is 0.1-0.3)
    const complexity = totalDeviation / (this.mousePoints.length - 2);
    return Math.min(1, complexity);
  }

  /**
   * Analyzes keystroke timing patterns.
   * Bots have very consistent timing, humans have variance.
   * @returns {Object} Keystroke timing stats
   */
  calculateKeystrokeTiming() {
    if (this.keystrokes.length < 4) {
      return { variance: 0, avgInterval: 0, count: 0 };
    }

    const intervals = [];
    for (let i = 1; i < this.keystrokes.length; i++) {
      intervals.push(this.keystrokes[i].t - this.keystrokes[i - 1].t);
    }

    const avg = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / intervals.length;

    return {
      variance: Math.round(variance),
      avgInterval: Math.round(avg),
      count: this.keystrokes.length
    };
  }

  /**
   * Analyzes scroll behavior patterns.
   * Bots often don't scroll or scroll in unnatural patterns.
   * @returns {Object} Scroll pattern stats
   */
  calculateScrollPattern() {
    if (this.scrollEvents.length < 2) {
      return { smoothness: 0, count: 0, totalDistance: 0 };
    }

    let totalDistance = 0;
    let maxJump = 0;

    for (let i = 1; i < this.scrollEvents.length; i++) {
      const dist = Math.abs(this.scrollEvents[i].y - this.scrollEvents[i - 1].y);
      totalDistance += dist;
      maxJump = Math.max(maxJump, dist);
    }

    // Smoothness: low max jump relative to total distance indicates smooth scrolling
    const smoothness = maxJump > 0 ? 1 - (maxJump / (totalDistance + 1)) : 0;

    return {
      smoothness: Math.round(smoothness * 100) / 100,
      count: this.scrollEvents.length,
      totalDistance: Math.round(totalDistance)
    };
  }

  /**
   * Calculates time from page load to first interaction.
   * Bots often interact immediately (< 100ms) or after a fixed delay.
   * @returns {number} Time to first interaction in milliseconds
   */
  calculateTimeToInteract() {
    if (this.firstInteractionTime === null) {
      return -1; // No interaction yet
    }
    return this.firstInteractionTime - this.startTime;
  }

  /**
   * Analyzes click/tap precision.
   * Bots often click with pixel-perfect precision or in suspicious patterns.
   * @returns {Object} Click precision stats
   */
  calculateClickPrecision() {
    if (this.clicks.length < 2) {
      return { variance: 0, count: 0, avgSpeed: 0 };
    }

    // Calculate variance in click positions
    const xCoords = this.clicks.map(c => c.x);
    const yCoords = this.clicks.map(c => c.y);

    const xAvg = xCoords.reduce((a, b) => a + b, 0) / xCoords.length;
    const yAvg = yCoords.reduce((a, b) => a + b, 0) / yCoords.length;

    const xVariance = xCoords.reduce((sum, val) => sum + Math.pow(val - xAvg, 2), 0) / xCoords.length;
    const yVariance = yCoords.reduce((sum, val) => sum + Math.pow(val - yAvg, 2), 0) / yCoords.length;

    const totalVariance = Math.sqrt(xVariance + yVariance);

    // Calculate average time between clicks
    const intervals = [];
    for (let i = 1; i < this.clicks.length; i++) {
      intervals.push(this.clicks[i].t - this.clicks[i - 1].t);
    }
    const avgSpeed = intervals.length > 0 ? intervals.reduce((a, b) => a + b, 0) / intervals.length : 0;

    return {
      variance: Math.round(totalVariance),
      count: this.clicks.length,
      avgSpeed: Math.round(avgSpeed)
    };
  }
}

/**
 * Detects behavioral anomalies that indicate bot activity.
 * @param {Object} signals Behavioral signals object
 * @returns {Array<string>} Array of detected anomalies
 */
export function detectBehavioralAnomalies(signals) {
  const anomalies = [];

  // Check for instant interaction (bot signature)
  if (signals.timeToInteract >= 0 && signals.timeToInteract < 100) {
    anomalies.push('instant_interaction');
  }

  // Check for perfectly straight mouse movement (bot signature)
  if (signals.mousePathComplexity > 0 && signals.mousePathComplexity < 0.01) {
    anomalies.push('straight_mouse_path');
  }

  // Check for zero mouse movement (headless/automation)
  if (signals.interactionCount < 5) {
    anomalies.push('minimal_interaction');
  }

  // Check for perfectly consistent keystroke timing (bot signature)
  if (signals.keystrokeTiming.count >= 5 && signals.keystrokeTiming.variance < 10) {
    anomalies.push('consistent_keystrokes');
  }

  // Check for pixel-perfect clicks (bot signature)
  if (signals.clickPrecision.count >= 3 && signals.clickPrecision.variance < 5) {
    anomalies.push('perfect_clicks');
  }

  // Check for suspiciously fast clicks (bot signature)
  if (signals.clickPrecision.avgSpeed > 0 && signals.clickPrecision.avgSpeed < 50) {
    anomalies.push('rapid_clicks');
  }

  // Check for no scroll activity on long page
  if (document.body.scrollHeight > window.innerHeight * 1.5 && signals.scrollPattern.count === 0) {
    anomalies.push('no_scroll');
  }

  return anomalies;
}
