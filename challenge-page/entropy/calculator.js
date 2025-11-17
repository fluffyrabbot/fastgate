// calculator.js - Entropy calculation and bot detection scoring
// Part of Phase 3: Privacy-preserving bot detection

import { detectHardwareAnomalies } from './hardware.js';
import { detectBehavioralAnomalies } from './behavior.js';
import { detectEnvironmentAnomalies, getEnvironmentHash } from './environment.js';

/**
 * Calculates Shannon entropy for a signal distribution.
 * H(X) = -Σ p(x) * log₂(p(x))
 * Higher entropy = more random/unpredictable = more human-like
 * @param {Array<number>} values Signal values
 * @returns {number} Shannon entropy
 */
export function calculateShannonEntropy(values) {
  if (values.length === 0) return 0;

  // Count frequencies
  const frequencies = new Map();
  for (const val of values) {
    frequencies.set(val, (frequencies.get(val) || 0) + 1);
  }

  // Calculate probabilities and entropy
  const n = values.length;
  let entropy = 0;

  for (const count of frequencies.values()) {
    const p = count / n;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }

  return entropy;
}

/**
 * Combines all signals into a comprehensive entropy profile.
 * @param {Object} hardware Hardware signals
 * @param {Object} behavioral Behavioral signals
 * @param {Object} environment Environment signals
 * @returns {Object} Complete entropy profile
 */
export function buildEntropyProfile(hardware, behavioral, environment) {
  // Detect anomalies across all categories
  const hardwareAnomalies = detectHardwareAnomalies(hardware);
  const behavioralAnomalies = detectBehavioralAnomalies(behavioral);
  const environmentAnomalies = detectEnvironmentAnomalies(environment);

  const allAnomalies = [
    ...hardwareAnomalies,
    ...behavioralAnomalies,
    ...environmentAnomalies
  ];

  // Calculate entropy scores for behavioral signals
  const mouseEntropy = calculateMouseEntropy(behavioral);
  const timingEntropy = calculateTimingEntropy(behavioral);
  const interactionEntropy = calculateInteractionEntropy(behavioral);

  // Calculate bot likelihood score (0.0 = human, 1.0 = bot)
  const botScore = calculateBotScore({
    hardwareAnomalies,
    behavioralAnomalies,
    environmentAnomalies,
    mouseEntropy,
    timingEntropy,
    interactionEntropy,
    hardware,
    behavioral,
    environment
  });

  return {
    version: '1.0',
    timestamp: Date.now(),
    scores: {
      bot: botScore,
      human: 1.0 - botScore,
      confidence: calculateConfidence(behavioral, hardware)
    },
    entropy: {
      mouse: mouseEntropy,
      timing: timingEntropy,
      interaction: interactionEntropy
    },
    anomalies: {
      hardware: hardwareAnomalies,
      behavioral: behavioralAnomalies,
      environment: environmentAnomalies,
      total: allAnomalies.length
    },
    signals: {
      hardware: sanitizeHardwareSignals(hardware),
      behavioral: sanitizeBehavioralSignals(behavioral),
      environment: sanitizeEnvironmentSignals(environment)
    },
    fingerprint: getEnvironmentHash(environment)
  };
}

/**
 * Calculates mouse movement entropy.
 * @param {Object} behavioral Behavioral signals
 * @returns {number} Mouse entropy score (0-5, higher is more human)
 */
function calculateMouseEntropy(behavioral) {
  if (!behavioral.mousePathComplexity || behavioral.mousePathComplexity === 0) {
    return 0;
  }

  // Human mouse movement typically has complexity of 0.1-0.3
  // Convert to entropy score (0-5 scale for compatibility with Shannon entropy)
  const complexity = behavioral.mousePathComplexity;

  if (complexity < 0.01) return 0; // Straight line (bot)
  if (complexity < 0.05) return 1; // Very simple
  if (complexity < 0.15) return 3; // Normal human
  if (complexity < 0.30) return 4; // Active human
  return 5; // Very active/erratic
}

/**
 * Calculates timing entropy from keystroke and click patterns.
 * @param {Object} behavioral Behavioral signals
 * @returns {number} Timing entropy score
 */
function calculateTimingEntropy(behavioral) {
  const timing = behavioral.keystrokeTiming;

  if (!timing || timing.count < 3) {
    return 0; // Not enough data
  }

  // High variance = more human-like
  // Normalize variance to 0-5 scale
  const variance = timing.variance;

  if (variance < 10) return 0; // Very consistent (bot)
  if (variance < 100) return 1; // Somewhat consistent
  if (variance < 500) return 3; // Normal human
  if (variance < 2000) return 4; // Active human
  return 5; // Very variable
}

/**
 * Calculates interaction pattern entropy.
 * @param {Object} behavioral Behavioral signals
 * @returns {number} Interaction entropy score
 */
function calculateInteractionEntropy(behavioral) {
  const count = behavioral.interactionCount || 0;

  if (count === 0) return 0; // No interaction (bot)
  if (count < 5) return 1; // Minimal interaction
  if (count < 20) return 2; // Some interaction
  if (count < 50) return 3; // Normal interaction
  if (count < 100) return 4; // Active interaction
  return 5; // Very active
}

/**
 * Calculates overall bot likelihood score.
 * Combines anomaly counts with entropy scores.
 * @param {Object} params All signals and anomalies
 * @returns {number} Bot score (0.0-1.0, higher = more likely bot)
 */
function calculateBotScore(params) {
  const {
    hardwareAnomalies,
    behavioralAnomalies,
    environmentAnomalies,
    mouseEntropy,
    timingEntropy,
    interactionEntropy,
    hardware,
    behavioral,
    environment
  } = params;

  let score = 0;
  let weights = 0;

  // Anomaly-based scoring (each anomaly adds to bot score)
  const totalAnomalies = hardwareAnomalies.length + behavioralAnomalies.length + environmentAnomalies.length;

  // Critical anomalies (very strong bot indicators)
  const criticalAnomalies = [
    'headless_swiftshader',
    'headless_ua',
    'phantom_ua',
    'instant_interaction',
    'straight_mouse_path',
    'perfect_clicks',
    'consistent_keystrokes'
  ];

  const criticalCount = [...hardwareAnomalies, ...behavioralAnomalies, ...environmentAnomalies]
    .filter(a => criticalAnomalies.includes(a)).length;

  // Critical anomalies have high weight
  if (criticalCount > 0) {
    score += criticalCount * 0.3;
    weights += 1;
  }

  // Total anomalies (moderate weight)
  if (totalAnomalies > 0) {
    score += Math.min(totalAnomalies * 0.1, 0.5);
    weights += 1;
  }

  // Entropy-based scoring (low entropy = bot-like)
  const avgEntropy = (mouseEntropy + timingEntropy + interactionEntropy) / 3;
  const entropyScore = 1.0 - (avgEntropy / 5.0); // Invert: low entropy = high bot score
  score += entropyScore * 0.5;
  weights += 1;

  // Time to interact (instant = bot)
  if (behavioral.timeToInteract >= 0) {
    if (behavioral.timeToInteract < 100) {
      score += 0.3; // Instant interaction (strong bot indicator)
    } else if (behavioral.timeToInteract < 500) {
      score += 0.1; // Very fast (moderate bot indicator)
    }
    weights += 1;
  }

  // WebGL consistency check
  if (hardware.webgl && !hardware.webgl.consistent) {
    score += 0.2;
    weights += 1;
  }

  // Missing features (environment)
  const missingFeatures = Object.values(environment.features || {}).filter(v => v === false).length;
  if (missingFeatures > 3) {
    score += 0.2;
    weights += 1;
  }

  // Normalize score
  const normalizedScore = weights > 0 ? score / weights : 0;

  // Clamp to [0, 1]
  return Math.max(0, Math.min(1, normalizedScore));
}

/**
 * Calculates confidence in the bot/human classification.
 * More interaction data = higher confidence.
 * @param {Object} behavioral Behavioral signals
 * @param {Object} hardware Hardware signals
 * @returns {number} Confidence score (0.0-1.0)
 */
function calculateConfidence(behavioral, hardware) {
  let confidence = 0;

  // Behavioral data available
  if (behavioral.interactionCount > 10) confidence += 0.3;
  else if (behavioral.interactionCount > 5) confidence += 0.2;
  else if (behavioral.interactionCount > 0) confidence += 0.1;

  // Hardware data available
  if (hardware.webgl && hardware.webgl.vendor !== 'unknown') confidence += 0.2;
  if (hardware.cores > 0) confidence += 0.1;

  // Timing data available
  if (behavioral.timeToInteract >= 0) confidence += 0.1;

  // WebGL consistency tested
  if (hardware.webgl && typeof hardware.webgl.consistent === 'boolean') confidence += 0.2;

  // RAF/jitter tested
  if (hardware.eventLoopJitter > 0 || hardware.rafVariance > 0) confidence += 0.1;

  return Math.min(1.0, confidence);
}

/**
 * Coarsens GPU vendor string to prevent fingerprinting.
 * @param {string} vendor Raw vendor string
 * @returns {string} Coarsened vendor category
 */
function coarsenVendor(vendor) {
  const vendorMap = {
    'nvidia': 'nvidia',
    'amd': 'amd',
    'intel': 'intel',
    'apple': 'apple',
    'swiftshader': 'swiftshader'
  };

  for (const [key, value] of Object.entries(vendorMap)) {
    if (vendor.includes(key)) {
      return value;
    }
  }
  return 'other';
}

/**
 * Sanitizes hardware signals for transmission (remove sensitive data).
 * @param {Object} hardware Hardware signals
 * @returns {Object} Sanitized signals
 */
function sanitizeHardwareSignals(hardware) {
  return {
    webgl: {
      // Coarsen vendor/renderer to prevent fingerprinting
      vendor: coarsenVendor(hardware.webgl.vendor),
      consistent: hardware.webgl.consistent
    },
    cores: hardware.cores > 0 ? Math.min(hardware.cores, 16) : -1, // Cap at 16 for privacy
    eventLoopJitter: Math.round(hardware.eventLoopJitter * 10) / 10,
    rafVariance: Math.round(hardware.rafVariance * 10) / 10,
    hasTouch: hardware.pointerTypes.touch,
    maxTouchPoints: hardware.pointerTypes.maxTouchPoints
  };
}

/**
 * Sanitizes behavioral signals for transmission.
 * @param {Object} behavioral Behavioral signals
 * @returns {Object} Sanitized signals
 */
function sanitizeBehavioralSignals(behavioral) {
  return {
    mousePathComplexity: Math.round(behavioral.mousePathComplexity * 100) / 100,
    keystrokeTiming: {
      variance: behavioral.keystrokeTiming.variance,
      count: behavioral.keystrokeTiming.count
    },
    scrollPattern: behavioral.scrollPattern,
    timeToInteract: behavioral.timeToInteract,
    clickPrecision: behavioral.clickPrecision,
    interactionCount: behavioral.interactionCount
  };
}

/**
 * Sanitizes environment signals for transmission.
 * @param {Object} environment Environment signals
 * @returns {Object} Sanitized signals
 */
function sanitizeEnvironmentSignals(environment) {
  return {
    screen: {
      bucket: environment.screen.bucket,
      orientation: environment.screen.orientation,
      pixelRatio: Math.round(environment.screen.pixelRatio * 10) / 10
    },
    timezone: {
      offset: environment.timezone.offset
      // Don't send timezone name for privacy
    },
    languages: {
      count: environment.languages.count
      // Don't send language codes for privacy
    },
    features: environment.features,
    colorDepth: environment.colorDepth,
    platform: {
      cookieEnabled: environment.platform.cookieEnabled,
      maxTouchPoints: environment.platform.maxTouchPoints
    },
    plugins: {
      count: environment.plugins.count
    }
  };
}

/**
 * Generates a human-readable summary of the entropy profile.
 * @param {Object} profile Entropy profile
 * @returns {string} Summary text
 */
export function summarizeProfile(profile) {
  const botPercent = Math.round(profile.scores.bot * 100);
  const humanPercent = Math.round(profile.scores.human * 100);
  const confidence = Math.round(profile.scores.confidence * 100);

  let summary = `Bot Likelihood: ${botPercent}% (Human: ${humanPercent}%, Confidence: ${confidence}%)\n`;

  if (profile.anomalies.total > 0) {
    summary += `Detected ${profile.anomalies.total} anomalies:\n`;
    if (profile.anomalies.hardware.length > 0) {
      summary += `  Hardware: ${profile.anomalies.hardware.join(', ')}\n`;
    }
    if (profile.anomalies.behavioral.length > 0) {
      summary += `  Behavioral: ${profile.anomalies.behavioral.join(', ')}\n`;
    }
    if (profile.anomalies.environment.length > 0) {
      summary += `  Environment: ${profile.anomalies.environment.join(', ')}\n`;
    }
  }

  summary += `\nEntropy Scores:\n`;
  summary += `  Mouse: ${profile.entropy.mouse.toFixed(2)}/5\n`;
  summary += `  Timing: ${profile.entropy.timing.toFixed(2)}/5\n`;
  summary += `  Interaction: ${profile.entropy.interaction.toFixed(2)}/5\n`;

  return summary;
}
