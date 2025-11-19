#!/usr/bin/env node

/**
 * Simple test origin server
 * Serves on port 3000 to simulate the backend behind FastGate
 */

const http = require('http');

const server = http.createServer((req, res) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} - Cookie: ${req.headers.cookie || 'none'}`);

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(`
<!DOCTYPE html>
<html>
<head>
  <title>Test Origin - Protected by FastGate</title>
  <style>
    body { font-family: system-ui; max-width: 800px; margin: 50px auto; padding: 20px; }
    .success { color: green; font-size: 2em; margin: 20px 0; }
    .cookie { background: #f0f0f0; padding: 10px; border-radius: 4px; word-break: break-all; }
  </style>
</head>
<body>
  <h1 class="success">✅ Success!</h1>
  <p>You've successfully passed the FastGate WebAuthn challenge and reached the protected origin.</p>

  <h2>Request Details:</h2>
  <p><strong>Path:</strong> ${req.url}</p>
  <p><strong>Method:</strong> ${req.method}</p>
  <p><strong>Clearance Cookie:</strong></p>
  <pre class="cookie">${req.headers.cookie || 'No cookie received'}</pre>

  <h2>What Just Happened:</h2>
  <ol>
    <li>Your browser was challenged by FastGate</li>
    <li>WebAuthn registered a credential using your platform authenticator (virtual)</li>
    <li>FastGate verified the attestation (packed format)</li>
    <li>You received a "hardware_attested" clearance token (24h TTL)</li>
    <li>You were redirected here with the token</li>
  </ol>

  <p><a href="/">Go to home</a> | <a href="/test">Test another path</a></p>
</body>
</html>
  `);
});

server.listen(3000, () => {
  console.log('🚀 Test origin server listening on http://localhost:3000');
  console.log('   This simulates your protected backend behind FastGate');
});
