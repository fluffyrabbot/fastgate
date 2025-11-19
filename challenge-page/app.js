// Import entropy modules
import { gatherHardwareSignals } from './entropy/hardware.js';
import { BehaviorTracker } from './entropy/behavior.js';
import { gatherEnvironmentSignals } from './entropy/environment.js';
import { buildEntropyProfile } from './entropy/calculator.js';

(function () {
  // ----- small helpers -----
  function qs(name, urlStr) {
    const url = urlStr || window.location.href;
    const rx = new RegExp("[?&]" + name.replace(/[\\[\\]]/g, "\\$&") + "(=([^&#]*)|&|#|$)");
    const m = rx.exec(url);
    if (!m) return null;
    if (!m[2]) return "";
    return decodeURIComponent(m[2].replace(/\+/g, " "));
  }
  function $(id) { return document.getElementById(id); }
  function setMsg(html) { $("msg").innerHTML = html; $("fallback").style.display = "block"; }
  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  function setFallbackHref(u) {
    var a = $("fallback-link"); if (a) a.href = u || "/";
    var b = $("noscript-link"); if (b) b.href = u || "/";
  }

  // Initialize behavior tracker early to capture all interactions
  const behaviorTracker = new BehaviorTracker();
  behaviorTracker.start();

  // Ensure we have WebCrypto
  if (!window.crypto || !window.crypto.subtle) {
    setMsg("Your browser is missing required crypto APIs. Please update or <a href=\"/\">try again</a>.");
    return;
  }

  const initialReturnUrl = qs("u") || "/";
  setFallbackHref(initialReturnUrl);

  // Base64url -> Uint8Array
  function b64urlToBytes(b64) {
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4; if (pad) b64 += "=".repeat(4 - pad);
    const str = atob(b64);
    const out = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i);
    return out;
  }

  // SHA-256(ArrayBuffer) -> Uint8Array
  function sha256(buf) { return crypto.subtle.digest("SHA-256", buf).then(x => new Uint8Array(x)); }

  // concat nonce || uint32_be(solution)
  function concatNonceSolution(nonceBytes, solution) {
    const b = new Uint8Array(nonceBytes.length + 4);
    b.set(nonceBytes, 0);
    b[nonceBytes.length + 0] = (solution >>> 24) & 0xff;
    b[nonceBytes.length + 1] = (solution >>> 16) & 0xff;
    b[nonceBytes.length + 2] = (solution >>> 8) & 0xff;
    b[nonceBytes.length + 3] = (solution >>> 0) & 0xff;
    return b;
  }

  function leadingZeroBits(bytes) {
    let n = 0;
    for (let i = 0; i < bytes.length; i++) {
      let by = bytes[i];
      for (let j = 7; j >= 0; j--) {
        if (((by >> j) & 1) === 0) n++; else return n;
      }
    }
    return n;
  }

  async function solvePow(nonceB64, bits) {
    const nonce = b64urlToBytes(nonceB64);
    // Tight loop, but yield every so often to keep UI responsive on slow devices.
    let solution = 0, iter = 0;
    while (true) {
      const buf = concatNonceSolution(nonce, solution >>> 0);
      const hash = await sha256(buf);
      if (leadingZeroBits(hash) >= bits) return (solution >>> 0);
      solution = (solution + 1) >>> 0;
      if (++iter % 4000 === 0) await sleep(0); // cooperative yield
    }
  }

  async function postJSON(path, body) {
    return fetch(path, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }

  async function countdown(seconds) {
    const end = Date.now() + seconds * 1000;
    while (true) {
      const left = Math.max(0, Math.ceil((end - Date.now()) / 1000));
      setMsg('The gate is busy. Retrying in <span class="mono">' + left + "s</span>…");
      if (left <= 0) break;
      await sleep(250);
    }
  }

  async function start() {
    try {
      let retURL = initialReturnUrl;

      // Try WebAuthn first (if supported and available)
      if (window.WebAuthnSolver && window.WebAuthnSolver.supportsWebAuthn()) {
        try {
          const hasPlatform = await window.WebAuthnSolver.hasPlatformAuthenticator();
          if (hasPlatform) {
            setMsg("Authenticating with your device...");
            await window.WebAuthnSolver.solveWebAuthnChallenge(retURL, setMsg);
            // If we get here, it succeeded and redirected
            return;
          }
        } catch (webauthnError) {
          console.log("WebAuthn failed, falling back to PoW:", webauthnError);
          // Fall through to PoW
        }
      }

      // Fallback to PoW challenge
      for (;;) {
        const nonceRes = await postJSON("/v1/challenge/nonce", { return_url: retURL });
        if (nonceRes.status === 429) {
          const ra = parseInt(nonceRes.headers.get("Retry-After") || "2", 10);
          await countdown(isFinite(ra) && ra > 0 ? ra : 2);
          continue;
        }
        if (!nonceRes.ok) {
          setMsg('Could not start the check. <a href="' + retURL + '">Try again</a>.');
          return;
        }
        const data = await nonceRes.json();
        // Server may echo a sanitized return_url; prefer it.
        if (data && typeof data.return_url === "string" && data.return_url.length) {
          retURL = data.return_url;
          setFallbackHref(retURL);
        }

        // 2) Solve PoW
        setMsg("Verifying… this should be quick.");
        const solution = await solvePow(String(data.nonce), Number(data.difficulty_bits || 16));

        // 2.5) Collect entropy signals after PoW completion
        const hardwareSignals = await gatherHardwareSignals();
        const behavioralSignals = behaviorTracker.getSignals();
        const environmentSignals = gatherEnvironmentSignals();

        // Build entropy profile
        const entropyProfile = buildEntropyProfile(
          hardwareSignals,
          behavioralSignals,
          environmentSignals
        );

        // Stop tracking (cleanup)
        behaviorTracker.stop();

        // 3) Complete challenge (issue clearance) and follow redirect
        const compRes = await postJSON("/v1/challenge/complete", {
          challenge_id: String(data.challenge_id),
          nonce: String(data.nonce),
          solution: solution >>> 0,
          return_url: retURL,
          ua_hints: {
            tz_offset_min: new Date().getTimezoneOffset(),
            language: navigator.language || "",
            platform: navigator.platform || "",
            hardwareConcurrency: navigator.hardwareConcurrency || 0,
            vendor: navigator.vendor || ""
          },
          entropy: entropyProfile
        });

        // Some proxies respond 302; fetch may follow or not. Respect Location header either way.
        const loc = compRes.headers.get("Location") || retURL;
        if (compRes.status === 302 || compRes.redirected || compRes.ok) {
          window.location.replace(loc);
          return;
        }

        // Otherwise, show a retry link
        setMsg('Could not verify your browser. <a href="' + retURL + '">Try again</a>.');
        return;
      }
    } catch (e) {
      console && console.error && console.error(e);
      setMsg('Something went wrong. <a href="' + (qs("u") || "/") + '">Try again</a>.');
    }
  }

  document.addEventListener("DOMContentLoaded", start);
})();
