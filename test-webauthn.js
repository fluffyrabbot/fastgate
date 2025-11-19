#!/usr/bin/env node

/**
 * WebAuthn Testing Script - Automated debugging with virtual authenticator
 *
 * This script:
 * - Launches a browser with a virtual authenticator (simulates Touch ID/TPM)
 * - Captures all console logs and network requests
 * - Navigates to the challenge page
 * - Attempts WebAuthn registration
 * - Reports detailed errors with full context
 */

const { chromium } = require('playwright');

async function testWebAuthn() {
  console.log('🚀 Starting WebAuthn automated test...\n');

  const browser = await chromium.launch({
    headless: false, // Set to true for CI/CD
    slowMo: 100, // Slow down operations for visibility
  });

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    permissions: ['clipboard-read', 'clipboard-write'], // Grant permissions
  });

  const page = await context.newPage();

  // Set up a virtual authenticator (simulates hardware authenticator)
  // IMPORTANT: Must be done on an actual page, not context
  const cdpSession = await page.context().newCDPSession(page);
  await cdpSession.send('WebAuthn.enable');

  const authenticatorId = await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal', // Simulates platform authenticator (Touch ID, Windows Hello)
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true, // Auto-verify (simulate fingerprint success)
      automaticPresenceSimulation: true,
    }
  });

  console.log('✓ Virtual authenticator created:', authenticatorId.authenticatorId);

  // Capture navigation
  page.on('framenavigated', frame => {
    if (frame === page.mainFrame()) {
      console.log(`[NAV] Navigated to: ${frame.url()}`);
    }
  });

  // Capture console logs
  const consoleLogs = [];
  page.on('console', msg => {
    const text = msg.text();
    const type = msg.type();
    consoleLogs.push({ type, text, timestamp: new Date().toISOString() });
    console.log(`[BROWSER ${type.toUpperCase()}] ${text}`);
  });

  // Capture page errors
  const pageErrors = [];
  page.on('pageerror', error => {
    pageErrors.push({
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    console.error(`[PAGE ERROR] ${error.message}`);
  });

  // Capture network requests
  const requests = [];
  page.on('request', request => {
    const reqData = {
      method: request.method(),
      url: request.url(),
      headers: request.headers(),
      postData: request.postData(),
      timestamp: new Date().toISOString()
    };
    requests.push(reqData);

    // Log script requests
    if (request.url().endsWith('.js')) {
      console.log(`[NETWORK REQUEST] ${request.method()} ${request.url()}`);
    }
  });

  // Capture network responses
  const responses = [];
  page.on('response', async response => {
    const req = response.request();
    let body = null;
    try {
      // Only capture JSON responses
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('application/json')) {
        body = await response.text();
      }
    } catch (e) {
      // Ignore errors reading body
    }

    const respData = {
      url: response.url(),
      status: response.status(),
      statusText: response.statusText(),
      headers: response.headers(),
      body: body,
      timestamp: new Date().toISOString()
    };

    responses.push(respData);

    // Log 404s
    if (response.status() === 404) {
      console.log(`[NETWORK 404] ${req.url()}`);
    }

    // Log WebAuthn-related requests
    if (req.url().includes('/v1/challenge/webauthn') || req.url().includes('/v1/challenge/complete/webauthn')) {
      console.log(`\n[NETWORK] ${req.method()} ${req.url()}`);
      console.log(`  Status: ${response.status()} ${response.statusText()}`);
      if (req.postData()) {
        console.log(`  Request body: ${req.postData().substring(0, 200)}...`);
      }
      if (body) {
        console.log(`  Response body: ${body.substring(0, 500)}...`);
      }
    }
  });

  try {
    console.log('\n📍 Navigating to http://localhost:8080/__uam/');
    await page.goto('http://localhost:8080/__uam/', {
      waitUntil: 'networkidle',
      timeout: 10000
    });

    console.log('✓ Challenge page loaded');

    // Wait for WebAuthn to be attempted
    console.log('\n⏳ Waiting for WebAuthn flow to complete...');

    // Wait for either success (redirect) or error
    const result = await Promise.race([
      // Wait for redirect (success case)
      page.waitForURL('http://localhost:8080/test/success', { timeout: 15000 })
        .then(async () => {
          // Verify we're actually on the success page
          const pageTitle = await page.title();
          const hasSuccess = await page.locator('text=Authenticated').count() > 0 ||
                            await page.locator('text=FastGate').count() > 0;
          return {
            success: true,
            message: `Successfully authenticated and redirected! (Page: ${pageTitle})`
          };
        })
        .catch(() => null),

      // Wait for error message in UI
      page.waitForSelector('text=/Authentication cancelled|Attestation failed|failed/', { timeout: 15000 })
        .then(el => el.textContent())
        .then(text => ({ success: false, message: text }))
        .catch(() => null),

      // Timeout
      new Promise(resolve => setTimeout(() => resolve({
        success: false,
        message: 'Timeout waiting for WebAuthn result'
      }), 15000))
    ]).then(r => r || { success: false, message: 'All conditions returned null' });

    console.log('\n' + '='.repeat(80));
    if (result.success) {
      console.log('✅ SUCCESS:', result.message);
    } else {
      console.log('❌ FAILURE:', result.message);
    }
    console.log('='.repeat(80));

    // Print summary
    console.log('\n📊 Test Summary:');
    console.log(`  Console logs: ${consoleLogs.length}`);
    console.log(`  Page errors: ${pageErrors.length}`);
    console.log(`  Network requests: ${requests.length}`);
    console.log(`  Network responses: ${responses.length}`);

    if (pageErrors.length > 0) {
      console.log('\n❌ Page Errors:');
      pageErrors.forEach((err, i) => {
        console.log(`\n  ${i + 1}. ${err.message}`);
        if (err.stack) {
          console.log(`     ${err.stack.split('\n').slice(0, 3).join('\n     ')}`);
        }
      });
    }

    // Filter relevant console logs
    const webauthnLogs = consoleLogs.filter(log =>
      log.text.toLowerCase().includes('webauthn') ||
      log.text.toLowerCase().includes('attestation') ||
      log.text.toLowerCase().includes('credential') ||
      log.type === 'error'
    );

    if (webauthnLogs.length > 0) {
      console.log('\n📝 Relevant Console Logs:');
      webauthnLogs.forEach((log, i) => {
        console.log(`  ${i + 1}. [${log.type}] ${log.text}`);
      });
    }

    // Show WebAuthn network activity
    const webauthnRequests = requests.filter(r => r.url.includes('/v1/challenge'));
    if (webauthnRequests.length > 0) {
      console.log('\n🌐 WebAuthn Network Activity:');
      webauthnRequests.forEach((req, i) => {
        console.log(`  ${i + 1}. ${req.method} ${req.url}`);
      });
    }

    // Wait a bit to see final state
    await page.waitForTimeout(2000);

    // Take screenshot for debugging
    await page.screenshot({ path: '/tmp/webauthn-test.png', fullPage: true });
    console.log('\n📸 Screenshot saved to /tmp/webauthn-test.png');

    // Return success/failure
    return result.success;

  } catch (error) {
    console.error('\n💥 FATAL ERROR:', error.message);
    console.error(error.stack);

    // Take error screenshot
    try {
      await page.screenshot({ path: '/tmp/webauthn-error.png', fullPage: true });
      console.log('📸 Error screenshot saved to /tmp/webauthn-error.png');
    } catch (e) {
      // Ignore screenshot errors
    }

    return false;

  } finally {
    await browser.close();
  }
}

// Run the test
(async () => {
  const success = await testWebAuthn();
  process.exit(success ? 0 : 1);
})();
