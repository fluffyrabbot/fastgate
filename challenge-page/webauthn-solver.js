// WebAuthn Solver - Handles hardware-backed authentication challenges
// Uses browser's WebAuthn API to create credentials with platform authenticators (TPM, Touch ID, etc.)

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

  // Base64URL decode (ArrayBuffer)
  function base64urlToBuffer(base64url) {
    // Convert base64url to base64
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - (base64.length % 4)) % 4;
    const padded = base64 + '='.repeat(padLen);

    // Decode base64 to binary string
    const binary = atob(padded);

    // Convert binary string to Uint8Array
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes.buffer;
  }

  // ArrayBuffer to base64URL
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

  // Create WebAuthn credential
  async function createCredential(options) {
    // Convert base64url fields to ArrayBuffers
    const publicKey = {
      challenge: base64urlToBuffer(options.publicKey.challenge),
      rp: options.publicKey.rp,
      user: {
        id: base64urlToBuffer(options.publicKey.user.id),
        name: options.publicKey.user.name,
        displayName: options.publicKey.user.displayName
      },
      pubKeyCredParams: options.publicKey.pubKeyCredParams,
      authenticatorSelection: options.publicKey.authenticatorSelection,
      attestation: options.publicKey.attestation,
      timeout: options.publicKey.timeout || 60000
    };

    // Exclude credentials if provided
    if (options.publicKey.excludeCredentials) {
      publicKey.excludeCredentials = options.publicKey.excludeCredentials.map(cred => ({
        type: cred.type,
        id: base64urlToBuffer(cred.id)
      }));
    }

    // Call WebAuthn API
    const credential = await navigator.credentials.create({ publicKey });

    if (!credential) {
      throw new Error('Credential creation failed');
    }

    return credential;
  }

  // Submit attestation to server
  async function submitAttestation(challengeId, credential, returnUrl) {
    // Convert ArrayBuffers to base64url
    const attestationObject = bufferToBase64url(credential.response.attestationObject);
    const clientDataJSON = bufferToBase64url(credential.response.clientDataJSON);

    const res = await fetch('/v1/challenge/complete/webauthn?challenge_id=' + encodeURIComponent(challengeId), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: attestationObject,
          clientDataJSON: clientDataJSON
        }
      })
    });

    if (res.status === 302 || res.redirected) {
      // Fetch automatically follows redirects, so check the final URL
      // If we were redirected, use the final URL; otherwise use the Location header or fallback
      const finalUrl = res.url;
      const location = (res.redirected && finalUrl) ? finalUrl :
                      (res.headers.get('Location') || returnUrl || '/');
      window.location.replace(location);
      return true;
    }

    if (!res.ok) {
      const error = await res.json().catch(() => ({ error: 'unknown' }));
      throw new Error('Attestation failed: ' + (error.error || res.status));
    }

    return true;
  }

  // Main WebAuthn flow
  async function solveWebAuthnChallenge(returnUrl, setMsg) {
    try {
      // Check support
      if (!supportsWebAuthn()) {
        throw new Error('WebAuthn not supported in this browser');
      }

      const hasPlatform = await hasPlatformAuthenticator();
      if (!hasPlatform) {
        throw new Error('No platform authenticator available (no Touch ID, Windows Hello, etc.)');
      }

      // Request challenge
      setMsg('Requesting authentication challenge...');
      const options = await requestWebAuthnChallenge(returnUrl);

      // Show user prompt
      setMsg('Please authenticate using your device (Touch ID, Windows Hello, etc.)');

      // Create credential (this triggers the OS authentication dialog)
      const credential = await createCredential(options);

      // Submit attestation
      setMsg('Verifying attestation...');
      await submitAttestation(options.challenge_id, credential, options.return_url || returnUrl);

      // Success - redirect happens in submitAttestation
      return true;

    } catch (error) {
      console.error('WebAuthn error:', error);

      // User-friendly error messages
      if (error.name === 'NotAllowedError') {
        throw new Error('Authentication cancelled or timed out');
      } else if (error.name === 'InvalidStateError') {
        throw new Error('Authenticator already registered');
      } else if (error.name === 'NotSupportedError') {
        throw new Error('Authenticator not supported');
      } else {
        throw error;
      }
    }
  }

  // Export to global scope
  window.WebAuthnSolver = {
    supportsWebAuthn: supportsWebAuthn,
    hasPlatformAuthenticator: hasPlatformAuthenticator,
    solveWebAuthnChallenge: solveWebAuthnChallenge
  };

})();
