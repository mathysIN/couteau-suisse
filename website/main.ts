import express from "express";
import net, { Socket } from "net";
import path from "path";
import fs from "fs";
import sqlite3 from "sqlite3";

const app = express();
app.use(express.urlencoded({ extended: true }));

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
