import express from "express";
import net, { Socket } from "net";
import path from "path";
import fs from "fs";
import sqlite3 from "sqlite3";

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // Pour accepter les payloads JSON

// Simple rate limiting to demonstrate flood attack effects
const requestCounts = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT = 100; // Max requests per window
const RATE_WINDOW = 10000; // 10 seconds

app.use((req, res, next) => {
  const ip = req.ip || 'unknown';
  const now = Date.now();

  if (!requestCounts.has(ip)) {
    requestCounts.set(ip, { count: 1, resetTime: now + RATE_WINDOW });
    return next();
  }

  const record = requestCounts.get(ip)!;

  if (now > record.resetTime) {
    record.count = 1;
    record.resetTime = now + RATE_WINDOW;
    return next();
  }

  record.count++;

  if (record.count > RATE_LIMIT) {
    console.log(`[RATE LIMIT] Blocked request from ${ip} (${record.count} requests)`);
    return res.status(429).send('Too Many Requests - Rate limit exceeded');
  }

  // Simulate slowdown as load increases
  if (record.count > RATE_LIMIT * 0.7) {
    setTimeout(() => next(), 200); // Slow response
  } else {
    next();
  }
});

const DB_PATH = path.join(__dirname, "products.db");

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new sqlite3.Database(DB_PATH);

function initDatabase() {
  db.serialize(() => {
    db.run("DROP TABLE IF EXISTS products");
    db.run(`
      CREATE TABLE products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        color TEXT NOT NULL,
        price REAL NOT NULL,
        stock INTEGER NOT NULL
      )
    `);

    const products = [
      ["Apple", "Red", 0.99, 120],
      ["Banana", "Yellow", 0.59, 200],
      ["Orange", "Orange", 1.29, 150],
      ["Kiwi", "Brown", 1.49, 80],
      ["Strawberry", "Red", 2.99, 60],
      ["Blueberry", "Blue", 3.49, 50],
      ["Pineapple", "Yellow", 2.49, 40],
      ["Mango", "Orange", 1.99, 70],
      ["Grapes", "Purple", 2.19, 100],
      ["Watermelon", "Green", 4.99, 30],
    ];

    const stmt = db.prepare(
      "INSERT INTO products (name, color, price, stock) VALUES (?, ?, ?, ?)"
    );
    products.forEach((p) => stmt.run(p));
    stmt.finalize();
    console.log("Database initialized with sample products");
  });
}

initDatabase();

function renderTemplate(
  filePath: string,
  vars: Record<string, string>
): string {
  let content = fs.readFileSync(filePath, "utf-8");
  for (const key in vars) {
    content = content.replace(`\${${key}}`, vars[key]);
  }
  return content;
}

app.get("/", (_req, res) => {
  const html = renderTemplate(path.join(__dirname, "pages/index.html"), {
    user: "John",
    time: new Date().toLocaleTimeString(),
  });
  res.send(html);
});

app.post("/search", (_req, res) => {
  const searched = `${_req.body.searched ?? ""}`;

  const vulnerableQuery = `SELECT * FROM products WHERE name LIKE '%${searched}%'`;

  console.log("Executing query:", vulnerableQuery);

  db.all(vulnerableQuery, [], (err, rows: any[]) => {
    let searchResult = "";

    if (err) {
      searchResult = `<div style="color: red; font-family: monospace;">SQL Error: ${err.message}</div>`;
    } else if (rows && rows.length > 0) {
      searchResult = rows
        .map((d) => `${d.name} (${d.color}) - ${d.price}€ [Stock: ${d.stock}]`)
        .join("<br/>");
    } else {
      searchResult = "No results found";
    }

    const html = renderTemplate(path.join(__dirname, "pages/search.html"), {
      searched: searched,
      searchResult: searchResult,
    });
    res.send(html);
  });
});

// Vulnerable Login - No rate limiting
const VALID_CREDENTIALS = { username: "admin", password: "password123" };

app.get("/login", (_req, res) => {
  const html = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-100 p-8">
    <div class="max-w-md mx-auto bg-white rounded-lg shadow-sm p-8">
      <h1 class="text-2xl font-semibold text-gray-800 mb-6 text-center">Login</h1>

      <form action="/login" method="POST" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-2">Username</label>
          <input
            type="text"
            name="username"
            class="w-full px-4 py-3 border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-gray-400"
            required
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 mb-2">Password</label>
          <input
            type="password"
            name="password"
            class="w-full px-4 py-3 border border-gray-300 rounded focus:outline-none focus:ring-1 focus:ring-gray-400"
            required
          />
        </div>
        <button
          type="submit"
          class="w-full px-6 py-3 bg-gray-800 text-white font-medium rounded hover:bg-gray-700"
        >
          Login
        </button>
      </form>

      <div class="mt-6">
        <a href="/" class="text-gray-600 hover:underline">← Back to Home</a>
      </div>
    </div>
  </body>
</html>`;
  res.send(html);
});

app.post("/login", (_req, res) => {
  const username = `${_req.body.username ?? ""}`;
  const password = `${_req.body.password ?? ""}`;

  console.log(`Login attempt: ${username}:${password}`);

  // Support JSON response for automated tools
  const acceptsJson = _req.headers.accept?.includes('application/json');

  if (username === VALID_CREDENTIALS.username && password === VALID_CREDENTIALS.password) {
    if (acceptsJson) {
      res.json({ success: true, message: "Login Successful", username: username });
    } else {
      res.send(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-100 p-8">
    <div class="max-w-md mx-auto bg-white rounded-lg shadow-sm p-8">
      <div class="text-center">
        <h1 class="text-2xl font-semibold text-gray-800 mb-4">Login Successful</h1>
        <p class="text-gray-600 mb-6">Welcome, ${username}</p>
        <a href="/login" class="inline-block px-6 py-3 bg-gray-600 text-white rounded hover:bg-gray-700">
          Back to Login
        </a>
      </div>
    </div>
  </body>
</html>`);
    }
    } else {
      if (acceptsJson) {
        res.json({ success: false, message: "Invalid credentials" });
      } else {
        res.send(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-100 p-8">
    <div class="max-w-md mx-auto bg-white rounded-lg shadow-sm p-8">
      <div class="text-center">
        <h1 class="text-2xl font-semibold text-gray-800 mb-4">Login Failed</h1>
        <p class="text-gray-600 mb-6">Invalid username or password</p>
        <a href="/login" class="inline-block px-6 py-3 bg-gray-600 text-white rounded hover:bg-gray-700">
          Try Again
        </a>
      </div>
    </div>
  </body>
</html>`);
    }
  }
});

// ============================================================================
// VULNERABLE ENDPOINTS
// ============================================================================

// 1. PROTOTYPE POLLUTION - Vulnerable endpoint
app.post("/api/config", (_req, res) => {
  console.log("[VULN] Prototype Pollution endpoint accessed");
  
  const config: any = {};
  
  // Vulnerability: Merge user input without sanitization
  function merge(target: any, source: any): any {
    for (const key in source) {
      if (typeof source[key] === 'object' && source[key] !== null) {
        if (!target[key]) {
          target[key] = {};
        }
        merge(target[key], source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  
  try {
    const userConfig = _req.body;
    merge(config, userConfig);
    
    // Check if prototype was polluted
    const testObj: any = {};
    if (testObj.polluted) {
      console.log("[!] VULNERABLE: Object.prototype was polluted!");
      res.status(200).json({
        status: "vulnerable",
        message: "Configuration updated - prototype pollution detected!",
        polluted: testObj.polluted
      });
    } else {
      res.status(200).json({
        status: "success",
        message: "Configuration updated",
        config: config
      });
    }
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// VERIFICATION ENDPOINT - Pour prouver que la pollution a fonctionné
app.get("/api/verify-pollution", (_req, res) => {
  console.log("[VERIFY] Checking for prototype pollution...");
  
  // Créer un nouvel objet vide
  const testObject: any = {};
  
  // Vérifier les propriétés polluées
  const result = {
    polluted: testObject.polluted !== undefined,
    isAdmin: testObject.isAdmin,
    role: testObject.role,
    privileges: testObject.privileges,
    exploited: testObject.exploited,
    message: testObject.polluted ? "🚨 CONFIRMED: Object.prototype was polluted!" : "No pollution detected"
  };
  
  res.json(result);
});

// 2. XSS - Vulnerable search endpoint (reflects user input)
app.get("/api/search", (_req, res) => {
  const query = _req.query.search || "";
  console.log(`[VULN] XSS endpoint - search query: ${query}`);
  
  // Vulnerability: No sanitization - reflects user input directly
  const html = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>Search Results</title>
    <script src="https://code.jquery.com/jquery-1.12.3.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/lodash@4.17.11/lodash.min.js"></script>
  </head>
  <body>
    <h1>Search Results</h1>
    <p>You searched for: ${query}</p>
    <div id="results">
      <!-- User input is reflected here without escaping -->
      ${query}
    </div>
    <script>
      // jQuery vulnerable to XSS
      $(document).ready(function() {
        $('#results').html('${query}');
      });
    </script>
  </body>
</html>`;
  
  res.send(html);
});

// 3. DEPENDENCY CONFUSION - Expose package.json
app.get("/package.json", (_req, res) => {
  console.log("[VULN] package.json exposed");
  const packagePath = path.join(__dirname, "../package.json");
  
  if (fs.existsSync(packagePath)) {
    res.sendFile(packagePath);
  } else {
    res.status(404).json({ error: "package.json not found" });
  }
});

// 4. Additional vulnerable endpoint - Config file exposure
app.get("/.env", (_req, res) => {
  console.log("[VULN] .env file access attempted");
  res.send(`DB_HOST=localhost
DB_USER=admin
DB_PASSWORD=SuperSecret123!
API_KEY=sk-1234567890abcdef
JWT_SECRET=my-ultra-secret-jwt-key`);
});

// ============================================================================
// END VULNERABLE ENDPOINTS
// ============================================================================

// Fake administration page (for directory scanner testing)
app.get("/administration", (_req, res) => {
  const html = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Administration Panel</title>
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-900 p-8 min-h-screen flex items-center justify-center">
    <div class="max-w-md w-full bg-gray-800 rounded-xl shadow-2xl p-8 border border-gray-700">
      <div class="text-center mb-8">
        <div class="text-5xl mb-4">🔒</div>
        <h1 class="text-2xl font-bold text-white">Administration Panel</h1>
        <p class="text-gray-400 text-sm mt-2">Authorized personnel only</p>
      </div>

      <form action="/administration" method="POST" class="space-y-6">
        <div>
          <label class="block text-sm font-medium text-gray-300 mb-2">Admin Username</label>
          <input
            type="text"
            name="admin_user"
            placeholder="administrator"
            class="w-full px-4 py-3 bg-gray-700 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
            required
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-300 mb-2">Admin Password</label>
          <input
            type="password"
            name="admin_pass"
            placeholder="••••••••"
            class="w-full px-4 py-3 bg-gray-700 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
            required
          />
        </div>
        <button
          type="submit"
          class="w-full px-6 py-3 bg-red-600 text-white font-medium rounded-lg hover:bg-red-700 transition-colors"
        >
          Access Panel
        </button>
      </form>

      <div class="mt-6 text-center">
        <a href="/" class="text-gray-400 hover:text-white text-sm">← Back to Home</a>
      </div>

      <div class="mt-8 bg-yellow-900/30 border border-yellow-600/50 rounded-lg p-4 text-sm">
        <p class="text-yellow-400 font-semibold">⚠️ Hidden admin page</p>
        <p class="text-yellow-300/70 mt-1">This page was discovered via directory enumeration.</p>
      </div>
    </div>
  </body>
</html>`;
  res.send(html);
});

app.post("/administration", (_req, res) => {
  const html = `<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <script src="https://cdn.tailwindcss.com"></script>
  </head>
  <body class="bg-gray-900 p-8 min-h-screen flex items-center justify-center">
    <div class="max-w-md w-full bg-gray-800 rounded-xl shadow-2xl p-8 border border-red-500 text-center">
      <div class="text-6xl mb-4">🚫</div>
      <h1 class="text-2xl font-bold text-red-500 mb-4">Access Denied</h1>
      <p class="text-gray-400 mb-6">Invalid credentials. This attempt has been logged.</p>
      <a href="/administration" class="inline-block px-6 py-3 bg-gray-700 text-white rounded-lg hover:bg-gray-600">
        Try Again
      </a>
    </div>
  </body>
</html>`;
  res.send(html);
});



const HTTP_PORT = 80;
const FALLBACK_PORT = 3000;

app
  .listen(HTTP_PORT, () => {
    console.log(`HTTP server on port ${HTTP_PORT}`);
  })
  .on("error", (err: any) => {
    if (err.code === "EACCES") {
      console.log(
        `Port ${HTTP_PORT} requires root privileges. Starting on port ${FALLBACK_PORT} instead...`
      );
      app.listen(FALLBACK_PORT, () => {
        console.log(`HTTP server on port ${FALLBACK_PORT}`);
      });
    } else {
      throw err;
    }
  });

const ftpServer = net.createServer((socket: Socket) => {
  socket.write("220 Fake FTP ready\r\n");
});
ftpServer
  .listen(21, () => {
    console.log("Fake FTP on port 21");
  })
  .on("error", (err: any) => {
    if (err.code === "EACCES") {
      console.log("FTP server (port 21) requires root privileges - skipping");
    } else {
      console.error("FTP server error:", err.message);
    }
  });

const sshFake = net.createServer((socket: Socket) => {
  socket.write("SSH-2.0-OpenSSH_Fake\r\n");
});
sshFake
  .listen(22, () => {
    console.log("Fake SSH on port 22");
  })
  .on("error", (err: any) => {
    if (err.code === "EACCES") {
      console.log("SSH server (port 22) requires root privileges - skipping");
    } else {
      console.error("SSH server error:", err.message);
    }
  });
