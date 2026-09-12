/**
 * Vulnerable Fastify applications for DAST exploit replay.
 *
 * Each endpoint is intentionally vulnerable to a specific class.
 * Run inside a sandboxed environment for safe exploit verification.
 *
 * Usage:
 *   node vulnerable_app_js.js --class SQLi --port 3000
 *   node vulnerable_app_js.js --all --port 3000
 */

const http = require('http');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const url = require('url');

// ---------------------------------------------------------------------------
// SQL Injection
// ---------------------------------------------------------------------------
function createSqliHandler() {
  const db = { users: [
    { id: 1, username: 'admin', password: 'supersecret123', role: 'admin' },
    { id: 2, username: 'user', password: 'password123', role: 'user' },
  ]};

  return (req, res) => {
    const parsed = url.parse(req.url, true);
    const name = parsed.query.name || '';

    // VULNERABLE: naive SQL-like filter that gets bypassed with injection
    const query = `SELECT * FROM users WHERE username LIKE '%${name}%'`;
    let results;
    if (name.includes("'") || name.includes('"') || name.toLowerCase().includes(' or ')) {
      // Injection detected - returns ALL rows (simulates OR 1=1)
      results = db.users;
    } else {
      results = db.users.filter(u => u.username.toLowerCase().includes(name.toLowerCase()));
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(results.map(u => ({ id: u.id, username: u.username, role: u.role }))));
  };
}

// ---------------------------------------------------------------------------
// Path Traversal
// ---------------------------------------------------------------------------
function createPathTraversalHandler() {
  const BASE_DIR = '/tmp';
  // Create test files
  fs.writeFileSync(path.join(BASE_DIR, 'secret.txt'), 'SECRET_DATA_42');
  fs.writeFileSync(path.join(BASE_DIR, 'config.json'), JSON.stringify({ api_key: 'leaked-key-123' }));

  return (req, res) => {
    const parsed = url.parse(req.url, true);
    const name = parsed.query.name || '';

    // VULNERABLE: no path sanitization
    const filepath = path.join(BASE_DIR, name);
    try {
      const content = fs.readFileSync(filepath, 'utf-8');
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(content);
    } catch (e) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('File not found');
    }
  };
}

// ---------------------------------------------------------------------------
// Command Injection
// ---------------------------------------------------------------------------
function createCommandInjectionHandler() {
  return (req, res) => {
    const parsed = url.parse(req.url, true);
    const host = parsed.query.host || '127.0.0.1';

    // VULNERABLE: unsanitized input in shell command
    try {
      const output = execSync(`ping -c 1 ${host}`, { timeout: 5000, encoding: 'utf-8' });
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<pre>${output}</pre>`);
    } catch (e) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      res.end(`Error: ${e.message}`);
    }
  };
}

// ---------------------------------------------------------------------------
// XSS (Cross-Site Scripting)
// ---------------------------------------------------------------------------
function createXSSHandler() {
  return (req, res) => {
    const parsed = url.parse(req.url, true);
    const q = parsed.query.q || '';

    // VULNERABLE: reflected XSS
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<p>Search results for: ${q}</p>`);
  };
}

// ---------------------------------------------------------------------------
// SSRF (Server-Side Request Forgery)
// ---------------------------------------------------------------------------
function createSSRFHandler() {
  return (req, res) => {
    const parsed = url.parse(req.url, true);
    const targetUrl = parsed.query.url || '';

    if (!targetUrl) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Missing url parameter');
      return;
    }

    // VULNERABLE: no URL validation
    const clientReq = http.get(targetUrl, { timeout: 5000 }, (clientRes) => {
      let data = '';
      clientRes.on('data', chunk => { data += chunk; });
      clientRes.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(data.substring(0, 2000));
      });
    });

    clientReq.on('error', (e) => {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end(`Error: ${e.message}`);
    });

    clientReq.on('timeout', () => {
      clientReq.destroy();
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('Request timed out');
    });
  };
}

// ---------------------------------------------------------------------------
// Open Redirect
// ---------------------------------------------------------------------------
function createOpenRedirectHandler() {
  return (req, res) => {
    const parsed = url.parse(req.url, true);
    const targetUrl = parsed.query.url || '/';

    // VULNERABLE: no URL validation
    res.writeHead(302, {
      'Location': targetUrl,
      'Content-Type': 'text/html',
    });
    res.end(`<html><body>Redirecting to: <a href="${targetUrl}">${targetUrl}</a></body></html>`);
  };
}

// ---------------------------------------------------------------------------
// Internal Metadata (for SSRF testing)
// ---------------------------------------------------------------------------
function createMetadataHandler() {
  return (req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('instance-id\nami-id\nlocal-ipv4');
  };
}

// ---------------------------------------------------------------------------
// App Registry
// ---------------------------------------------------------------------------
const APP_REGISTRY = {
  SQLi: { handler: createSqliHandler, endpoint: '/search', param: 'name' },
  PathTraversal: { handler: createPathTraversalHandler, endpoint: '/files', param: 'name' },
  CommandInjection: { handler: createCommandInjectionHandler, endpoint: '/ping', param: 'host' },
  XSS: { handler: createXSSHandler, endpoint: '/xss', param: 'q' },
  SSRF: { handler: createSSRFHandler, endpoint: '/fetch', param: 'url' },
  OpenRedirect: { handler: createOpenRedirectHandler, endpoint: '/redirect', param: 'url' },
};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------
function createRouter(classes) {
  const routes = {};

  // Always add metadata endpoint for SSRF testing
  routes['/internal/metadata'] = createMetadataHandler();

  for (const cls of classes) {
    const app = APP_REGISTRY[cls];
    if (app) {
      routes[app.endpoint] = app.handler();
    }
  }

  return (req, res) => {
    const parsed = url.parse(req.url, true);
    const handler = routes[parsed.pathname];
    if (handler) {
      handler(req, res);
    } else {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end('<h1>Fastify Vulnerable App</h1><p>Available endpoints: ' +
        Object.keys(routes).join(', ') + '</p>');
    }
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
  const args = process.argv.slice(2);
  let port = 3000;
  let classes = [];

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port' && args[i + 1]) {
      port = parseInt(args[i + 1], 10);
      i++;
    } else if (args[i] === '--class' && args[i + 1]) {
      classes.push(args[i + 1]);
      i++;
    } else if (args[i] === '--all') {
      classes = Object.keys(APP_REGISTRY);
    }
  }

  if (classes.length === 0) {
    classes = Object.keys(APP_REGISTRY);
  }

  const router = createRouter(classes);
  const server = http.createServer(router);

  server.listen(port, '127.0.0.1', () => {
    console.log(`Fastify vulnerable app (${classes.join(', ')}) listening on 127.0.0.1:${port}`);
  });

  // Graceful shutdown
  process.on('SIGTERM', () => { server.close(); process.exit(0); });
  process.on('SIGINT', () => { server.close(); process.exit(0); });
}

if (require.main === module) {
  main();
}

module.exports = { APP_REGISTRY, createRouter };
