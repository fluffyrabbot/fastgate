// WebAuthn Solver - Handles hardware-backed authentication challenges
// Uses browser's WebAuthn API to get an assertion from a platform authenticator (TPM, Touch ID, etc.)

(function() {
  'use strict';

  // Check if WebAuthn is supported
  function supportsWebAuthn() {
    return window.PublicKeyCredential !== undefined &&
           typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
  }

  // Check if platform authenticator is available (async)
  async function hasPlatformAuthenticator() {
    if (!supportsWebAuthn()) return false;
    try {
      return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (e) {
      console.error('Error checking platform authenticator:', e);
      return false;
    }
  }

  // Base64URL to ArrayBuffer
  function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // ArrayBuffer to Base64URL
  function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    const base64 = btoa(binary);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  // Request WebAuthn challenge from server
  async function requestWebAuthnChallenge(returnUrl) {
    const res = await fetch('/v1/challenge/webauthn', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ return_url: returnUrl })
    });
    if (!res.ok) {
      throw new Error('Failed to request challenge: ' + res.status);
    }
    return await res.json();
  }

  // Get WebAuthn credential assertion
  async function getCredential(options) {
    const publicKey = {
      challenge: base64urlToBuffer(options.publicKey.challenge),
      rpId: options.publicKey.rpId,
      allowCredentials: [], // Empty for discoverable credentials
      userVerification: options.publicKey.userVerification,
      timeout: options.publicKey.timeout || 60000,
    };

    // Call WebAuthn API for authentication
    const credential = await navigator.credentials.get({ publicKey });

    if (!credential) {
      throw new Error('Authentication assertion failed');
    }
    return credential;
  }

  // Submit assertion to server
  async function submitAssertion(challengeId, credential, returnUrl) {
    const res = await fetch('/v1/challenge/complete/webauthn?challenge_id=' + encodeURIComponent(challengeId), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      redirect: 'manual',
      body: JSON.stringify({
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: bufferToBase64url(credential.response.authenticatorData),
          clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
          signature: bufferToBase64url(credential.response.signature),
          userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null,
        }
      })
    });

    if (res.status === 302 || res.redirected) {
      const location = res.headers.get('Location') || returnUrl || '/';
      window.location.replace(location);
      return true;
    }

    if (!res.ok) {
      const error = await res.json().catch(() => ({ error: 'unknown' }));
      throw new Error('Assertion failed: ' + (error.error || res.status));
    }
    return true;
  }

  // Main WebAuthn flow
  async function solveWebAuthnChallenge(returnUrl, setMsg) {
    try {
      if (!supportsWebAuthn() || !(await hasPlatformAuthenticator())) {
        throw new Error('No platform authenticator available (no Touch ID, Windows Hello, etc.)');
      }

      setMsg('Requesting authentication challenge...');
      const options = await requestWebAuthnChallenge(returnUrl);

      setMsg('Please authenticate using your device (Touch ID, Windows Hello, etc.)');
      const credential = await getCredential(options);

      setMsg('Verifying assertion...');
      await submitAssertion(options.challenge_id, credential, options.return_url || returnUrl);
      
      return true;

    } catch (error) {
      console.error('WebAuthn error:', error);
      if (error.name === 'NotAllowedError') {
        throw new Error('Authentication cancelled or timed out');
      }
      throw error; // Rethrow other errors to be caught by the main app.js
    }
  }

  // Export to global scope
  window.WebAuthnSolver = {
    supportsWebAuthn: supportsWebAuthn,
    hasPlatformAuthenticator: hasPlatformAuthenticator,
    solveWebAuthnChallenge: solveWebAuthnChallenge
  };

})();

