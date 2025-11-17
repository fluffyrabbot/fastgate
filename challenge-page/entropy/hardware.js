// hardware.js - Hardware signal collection for behavioral entropy fingerprinting
// Part of Phase 3: Privacy-preserving bot detection

/**
 * Gathers hardware-backed signals for entropy calculation.
 * These signals are difficult for simple bots to spoof correctly.
 * @returns {Promise<Object>} Hardware signals object
 */
export async function gatherHardwareSignals() {
  const signals = {
    webgl: await getWebGLInfo(),
    cores: getCores(),
    eventLoopJitter: await measureEventLoopJitter(),
    rafVariance: await measureRAFVariance(),
    pointerTypes: detectPointerTypes(),
    timestamp: Date.now()
  };

  return signals;
}

/**
 * Extracts WebGL vendor and renderer information.
 * Headless browsers often expose "SwiftShader" or generic strings.
 * @returns {Object} WebGL info with vendor, renderer, and consistency flag
 */
async function getWebGLInfo() {
  try {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

    if (!gl) {
      return { vendor: 'none', renderer: 'none', consistent: false };
    }

    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    let vendor = 'unknown';
    let renderer = 'unknown';

    if (debugInfo) {
      vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) || 'unknown';
      renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) || 'unknown';
    }

    // Test WebGL rendering consistency (headless often has non-deterministic rendering)
    const consistent = await testWebGLConsistency(gl);

    return {
      vendor: vendor.toLowerCase(),
      renderer: renderer.toLowerCase(),
      consistent
    };
  } catch (e) {
    return { vendor: 'error', renderer: 'error', consistent: false };
  }
}

/**
 * Tests WebGL rendering consistency by rendering the same scene multiple times.
 * Headless browsers often produce non-deterministic pixel data.
 * @param {WebGLRenderingContext} gl WebGL context
 * @returns {Promise<boolean>} True if rendering is consistent
 */
async function testWebGLConsistency(gl) {
  let vertexShader, fragmentShader, program, buffer;
  try {
    const size = 64;
    const canvas = gl.canvas;
    canvas.width = size;
    canvas.height = size;

    // Simple shader pair
    vertexShader = gl.createShader(gl.VERTEX_SHADER);
    gl.shaderSource(vertexShader, `
      attribute vec2 position;
      void main() {
        gl_Position = vec4(position, 0.0, 1.0);
      }
    `);
    gl.compileShader(vertexShader);

    fragmentShader = gl.createShader(gl.FRAGMENT_SHADER);
    gl.shaderSource(fragmentShader, `
      precision mediump float;
      void main() {
        gl_FragColor = vec4(0.5, 0.7, 0.3, 1.0);
      }
    `);
    gl.compileShader(fragmentShader);

    program = gl.createProgram();
    gl.attachShader(program, vertexShader);
    gl.attachShader(program, fragmentShader);
    gl.linkProgram(program);
    gl.useProgram(program);

    // Create a simple triangle
    buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([
      -0.5, -0.5,
       0.5, -0.5,
       0.0,  0.5
    ]), gl.STATIC_DRAW);

    const position = gl.getAttribLocation(program, 'position');
    gl.enableVertexAttribArray(position);
    gl.vertexAttribPointer(position, 2, gl.FLOAT, false, 0, 0);

    // Render 3 times and compare pixel data
    const samples = [];
    for (let i = 0; i < 3; i++) {
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.drawArrays(gl.TRIANGLES, 0, 3);

      const pixels = new Uint8Array(size * size * 4);
      gl.readPixels(0, 0, size, size, gl.RGBA, gl.UNSIGNED_BYTE, pixels);

      // Hash the pixel data for comparison
      let hash = 0;
      for (let j = 0; j < pixels.length; j++) {
        hash = ((hash << 5) - hash) + pixels[j];
        hash = hash & hash; // Convert to 32-bit integer
      }
      samples.push(hash);

      // Small delay between renders
      await new Promise(resolve => setTimeout(resolve, 5));
    }

    // All samples should be identical for consistent rendering
    return samples[0] === samples[1] && samples[1] === samples[2];
  } catch (e) {
    return false;
  } finally {
    // Cleanup WebGL resources to prevent memory leak
    if (buffer) gl.deleteBuffer(buffer);
    if (program) gl.deleteProgram(program);
    if (fragmentShader) gl.deleteShader(fragmentShader);
    if (vertexShader) gl.deleteShader(vertexShader);
  }
}

/**
 * Gets logical CPU core count.
 * @returns {number} Number of cores (or -1 if unavailable)
 */
function getCores() {
  return navigator.hardwareConcurrency || -1;
}

/**
 * Measures event loop timing jitter.
 * VMs and headless browsers often have higher variance.
 * @returns {Promise<number>} Jitter variance in milliseconds
 */
async function measureEventLoopJitter() {
  const samples = 10; // Reduced from 20 to minimize blocking time
  const delays = [];

  for (let i = 0; i < samples; i++) {
    const start = performance.now();
    await new Promise(resolve => setTimeout(resolve, 10));
    const end = performance.now();
    delays.push(end - start);
  }

  // Calculate variance
  const mean = delays.reduce((a, b) => a + b, 0) / delays.length;
  const variance = delays.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / delays.length;

  return Math.round(variance * 100) / 100; // Round to 2 decimal places
}

/**
 * Measures requestAnimationFrame timing variance.
 * Automation tools often have irregular RAF timing.
 * @returns {Promise<number>} RAF variance in milliseconds
 */
async function measureRAFVariance() {
  return new Promise((resolve) => {
    const samples = 15; // Reduced from 30 to minimize blocking time (~250ms at 60fps)
    const timestamps = [];
    let count = 0;

    function measure(timestamp) {
      timestamps.push(timestamp);
      count++;

      if (count < samples) {
        requestAnimationFrame(measure);
      } else {
        // Calculate frame time deltas
        const deltas = [];
        for (let i = 1; i < timestamps.length; i++) {
          deltas.push(timestamps[i] - timestamps[i - 1]);
        }

        // Calculate variance
        const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
        const variance = deltas.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / deltas.length;

        resolve(Math.round(variance * 100) / 100);
      }
    }

    requestAnimationFrame(measure);
  });
}

/**
 * Detects available pointer input types.
 * Bots often lack touch or pen support.
 * @returns {Object} Available pointer types
 */
function detectPointerTypes() {
  const hasTouch = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
  const hasPointer = 'PointerEvent' in window;
  const hasMouse = matchMedia('(pointer: fine)').matches;

  return {
    touch: hasTouch,
    pointer: hasPointer,
    mouse: hasMouse,
    maxTouchPoints: navigator.maxTouchPoints || 0
  };
}

/**
 * Detects known headless browser signatures in hardware signals.
 * @param {Object} signals Hardware signals object
 * @returns {Array<string>} Array of detected anomalies
 */
export function detectHardwareAnomalies(signals) {
  const anomalies = [];

  // Check for SwiftShader (common in headless Chrome)
  if (signals.webgl.renderer.includes('swiftshader')) {
    anomalies.push('headless_swiftshader');
  }

  // Check for generic/missing WebGL info
  if (signals.webgl.vendor === 'unknown' || signals.webgl.vendor === 'none') {
    anomalies.push('missing_webgl');
  }

  // Check for inconsistent rendering (headless signature)
  if (!signals.webgl.consistent) {
    anomalies.push('inconsistent_rendering');
  }

  // Check for missing cores info (rare on real browsers)
  if (signals.cores === -1) {
    anomalies.push('missing_cores');
  }

  // Check for impossible core counts (VMs often expose 1 or 2 cores)
  if (signals.cores === 1) {
    anomalies.push('single_core');
  }

  // Check for high event loop jitter (VM signature)
  if (signals.eventLoopJitter > 5.0) {
    anomalies.push('high_jitter');
  }

  // Check for high RAF variance (automation signature)
  if (signals.rafVariance > 10.0) {
    anomalies.push('high_raf_variance');
  }

  // Check for missing touch on mobile screen size
  const isMobileScreen = window.screen.width <= 768;
  if (isMobileScreen && !signals.pointerTypes.touch) {
    anomalies.push('mobile_no_touch');
  }

  return anomalies;
}
