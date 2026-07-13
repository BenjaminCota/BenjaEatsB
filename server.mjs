// ============================================================================
// MINI-SERVIDOR ESTÁTICO + LOGS DE SEGURIDAD
// Adaptación del módulo admin/logs de "secure-framework-lab" (Next.js) para un
// sitio estático puro (index.html + script.js + styles.css + assets/).
// Sin dependencias: solo usa módulos nativos de Node (no requiere package.json).
//
// Qué hace:
//   1) Sirve los archivos estáticos del sitio (este archivo va en la raíz,
//      junto a index.html).
//   2) Registra TODO el tráfico en .data/security-logs.json: visitas, rutas
//      inexistentes (404) y detecciones de ataque — patrones en la URL
//      (SQLi, XSS, path traversal, inyección de comandos), flood y enumeración
//      por IP, rutas-sonda de escáneres y user-agents de herramientas.
//   3) Expone el panel de administración en /admin (archivo admin.html)
//      protegido por contraseña, con API en /api/admin/logs (GET/DELETE).
//
// Uso:
//   node server.mjs
//   → sitio:  http://localhost:3000
//   → panel:  http://localhost:3000/admin
//
// Contraseña del panel: variable de entorno ADMIN_PASSWORD.
//   PowerShell:   $env:ADMIN_PASSWORD = "mi-clave"; node server.mjs
//   bash/mac:     ADMIN_PASSWORD=mi-clave node server.mjs
//   Si no se define, usa "admin123" (SOLO para pruebas locales).
// ============================================================================

import { createServer } from "node:http";
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { join, extname, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

const ROOT = dirname(fileURLToPath(import.meta.url));
const HOST = "0.0.0.0"; // todas las interfaces: otras máquinas pueden entrar
const PORT = Number(process.env.PORT) || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

// ---------------------------------------------------------------------------
// Almacén de logs: archivo JSON local, mismo formato que el módulo original.
// En producción se usaría una base de datos o un SIEM, nunca un archivo simple.
// ---------------------------------------------------------------------------
const DATA_DIR = join(ROOT, ".data");
const LOG_FILE = join(DATA_DIR, "security-logs.json");
const MAX_LOGS = 500; // rotación simple: conservamos solo los últimos N eventos

function readLogs() {
  try {
    if (!existsSync(LOG_FILE)) return [];
    return JSON.parse(readFileSync(LOG_FILE, "utf-8"));
  } catch {
    return [];
  }
}

function writeLogs(all) {
  try {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
    // Escritura síncrona: en Node (un solo hilo) es atómica respecto a otras
    // escrituras del mismo proceso, así el archivo no se corrompe.
    writeFileSync(LOG_FILE, JSON.stringify(all, null, 2), "utf-8");
  } catch {
    // Un fallo de logging nunca debe romper el servidor.
  }
}

// Palabras sensibles que NUNCA deben quedar guardadas en un log.
const SENSITIVE_WORDS = ["password", "token", "cookie", "cvv", "tarjeta", "card"];

function sanitizeMessage(message) {
  let safe = String(message);
  for (const word of SENSITIVE_WORDS) {
    const regex = new RegExp(`${word}\\s*[:=]\\s*\\S+`, "gi");
    safe = safe.replace(regex, `${word}: [OCULTO]`);
  }
  return safe;
}

// Punto único de escritura: agrega timestamp + id, sanitiza y persiste.
function logEvent(entry) {
  const full = {
    ...entry,
    message: sanitizeMessage(entry.message),
    referer: entry.referer ? sanitizeMessage(entry.referer) : entry.referer,
    timestamp: new Date().toISOString(),
    eventId: randomUUID(),
  };
  const all = readLogs();
  all.push(full);
  if (all.length > MAX_LOGS) all.splice(0, all.length - MAX_LOGS);
  writeLogs(all);
  console.log("[SECURITY]", JSON.stringify(full));
}

// ---------------------------------------------------------------------------
// Utilidades de IP y user-agent
// ---------------------------------------------------------------------------
function normalizeIp(ip) {
  const clean = (ip || "").trim();
  if (clean === "::1" || clean === "127.0.0.1") return "localhost";
  if (clean.startsWith("::ffff:")) {
    const ipv4 = clean.slice(7);
    return ipv4 === "127.0.0.1" ? "localhost" : ipv4;
  }
  return clean || "desconocida";
}

function parseUserAgent(ua) {
  const s = (ua || "").toLowerCase();
  if (!s) return "Desconocido";
  if (s.includes("sqlmap")) return "sqlmap (herramienta)";
  if (s.includes("nikto")) return "Nikto (escáner)";
  if (s.includes("nmap")) return "Nmap (escáner)";
  if (s.includes("zap")) return "OWASP ZAP (escáner)";
  if (s.includes("curl")) return "curl (línea de comandos)";
  if (s.includes("wget")) return "wget (línea de comandos)";
  if (s.includes("python-requests") || s.includes("go-http")) return "Cliente HTTP (script)";
  if (s.includes("postman")) return "Postman";
  let browser = "Navegador";
  if (s.includes("edg/")) browser = "Edge";
  else if (s.includes("opr/") || s.includes("opera")) browser = "Opera";
  else if (s.includes("firefox")) browser = "Firefox";
  else if (s.includes("chrome")) browser = "Chrome";
  else if (s.includes("safari")) browser = "Safari";
  let os = "";
  if (s.includes("windows")) os = "Windows";
  else if (s.includes("android")) os = "Android";
  else if (s.includes("iphone") || s.includes("ipad")) os = "iOS";
  else if (s.includes("mac os") || s.includes("macintosh")) os = "macOS";
  else if (s.includes("linux")) os = "Linux";
  return os ? `${browser} en ${os}` : browser;
}

// ---------------------------------------------------------------------------
// Detección de ataques (firmas simples, con fines educativos)
// ---------------------------------------------------------------------------
const ATTACK_PATTERNS = [
  { regex: /('|%27)?\s*(or|and)\s+\d+\s*=\s*\d+|union\s+select|;\s*drop\s+table|--\s|\/\*/i, label: "Inyección SQL" },
  { regex: /<script|onerror\s*=|onload\s*=|javascript:|<img\b|<svg\b/i, label: "Cross-Site Scripting (XSS)" },
  { regex: /\.\.\/|\.\.\\|\/etc\/passwd|c:\\windows/i, label: "Path Traversal" },
  { regex: /;\s*(ls|cat|whoami|id|dir)\b|\|\s*(whoami|cat|ls)\b|&&\s*\w+|`[^`]+`/i, label: "Inyección de comandos" },
];

// Rutas típicas que buscan los escáneres de vulnerabilidades.
const PROBE_PATHS = [
  ".php", ".env", "wp-login", "wp-admin", "phpmyadmin", "/.git", "/.aws",
  "server-info", "server-status", "config.json", "composer.lock", "id_rsa",
  "/actuator", "/console", "shell", "cgi-bin", "backup", ".sql", ".bak",
];

const SUSPICIOUS_AGENTS = ["sqlmap", "nikto", "nmap", "nessus", "acunetix", "zap", "dirbuster", "gobuster", "masscan"];

function scanForAttacks(text) {
  const found = [];
  for (const p of ATTACK_PATTERNS) if (p.regex.test(text)) found.push(p.label);
  return found;
}
function isProbePath(pathname) {
  const p = pathname.toLowerCase();
  return PROBE_PATHS.some((probe) => p.includes(probe));
}
function isSuspiciousUserAgent(ua) {
  const s = (ua || "").toLowerCase();
  return SUSPICIOUS_AGENTS.some((a) => s.includes(a));
}

// --- Comportamiento por IP: flood y enumeración (estado en memoria) ---
const ipActivity = new Map();
const BEHAVIOR_WINDOW_MS = 12_000;
const FLOOD_THRESHOLD = 15; // 15+ peticiones en la ventana = flood
const ENUM_THRESHOLD = 8; // 8+ rutas distintas en la ventana = enumeración

function registerIpRequest(ip, pathname) {
  const now = Date.now();
  let a = ipActivity.get(ip);
  if (!a) {
    a = { events: [], floodFlagged: false, enumFlagged: false };
    ipActivity.set(ip, a);
  }
  a.events = a.events.filter((e) => now - e.time <= BEHAVIOR_WINDOW_MS);
  if (a.events.length === 0) { a.floodFlagged = false; a.enumFlagged = false; }
  a.events.push({ time: now, path: pathname });
  const detected = [];
  if (a.events.length >= FLOOD_THRESHOLD && !a.floodFlagged) {
    a.floodFlagged = true;
    detected.push("Exceso de peticiones (flood / posible bot)");
  }
  const distinct = new Set(a.events.map((e) => e.path.split("?")[0]));
  if (distinct.size >= ENUM_THRESHOLD && !a.enumFlagged) {
    a.enumFlagged = true;
    detected.push("Enumeración de rutas (escaneo desde la misma IP)");
  }
  return detected;
}

// ---------------------------------------------------------------------------
// Registro del tráfico (se ejecuta cuando cada respuesta termina)
// ---------------------------------------------------------------------------
// Extensiones de sub-recursos que no registramos cuando cargan bien (ruido);
// si dan 404 SÍ se registran (puede ser una sonda de escaneo).
const QUIET_EXTENSIONS = /\.(css|js|mjs|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|webp|mp4|webm)$/i;

function shouldSkip(pathname, statusCode) {
  if (pathname.startsWith("/api/")) return true; // la API se registra a sí misma
  if (pathname === "/favicon.ico" || pathname === "/robots.txt") return true;
  if (QUIET_EXTENSIONS.test(pathname) && statusCode < 400) return true;
  return false;
}

function getRequestMeta(req) {
  const headers = req.headers;
  const userAgent = headers["user-agent"] || "desconocido";
  return {
    ip: normalizeIp((headers["x-forwarded-for"] || "").split(",")[0]),
    userAgent,
    client: parseUserAgent(userAgent),
    referer: headers["referer"] || headers["referrer"] || "-",
  };
}

function logTraffic(req, statusCode) {
  const rawUrl = req.url || "/";
  const pathname = rawUrl.split("?")[0];
  if (shouldSkip(pathname, statusCode)) return;

  const meta = getRequestMeta(req);

  // MODO EDUCATIVO: ?simip=1.2.3.4 permite simular otra IP desde el navegador.
  const simMatch = rawUrl.match(/[?&]simip=([^&\s]+)/i);
  if (simMatch) {
    const candidate = decodeURIComponent(simMatch[1]).trim();
    if (/^[0-9a-fA-F.:]+$/.test(candidate) && candidate.length <= 45) meta.ip = candidate;
  }

  const resource = rawUrl.slice(0, 200);
  const base = { ...meta, method: req.method || "GET", resource };

  // 1) Evento de VISITA (tráfico normal, incluye 404 de rutas inexistentes).
  logEvent({
    ...base,
    category: "VISIT",
    severity: "INFO",
    statusCode,
    message: statusCode === 404 ? "Petición a ruta inexistente" : "Visita / petición al servidor",
  });

  // 2) Comportamientos por IP (flood / enumeración).
  for (const behavior of registerIpRequest(meta.ip, resource)) {
    logEvent({
      ...base, category: "ATTACK", severity: "WARNING", statusCode: 429,
      attackTypes: [behavior],
      message: `Comportamiento sospechoso desde la IP ${meta.ip}: ${behavior}`,
    });
  }

  // 3) Patrones de ataque en la URL (decodificada, porque llegan URL-encoded).
  let decodedUrl = rawUrl;
  try {
    decodedUrl = decodeURIComponent(rawUrl.replace(/\+/g, " "));
  } catch {
    // URL mal formada: escaneamos la versión original.
  }
  const attacks = scanForAttacks(decodedUrl);
  if (attacks.length > 0) {
    logEvent({
      ...base, category: "ATTACK", severity: "ERROR", statusCode: statusCode || 400,
      attackTypes: attacks,
      message: `Posible ataque en la URL: ${attacks.join(", ")}`,
    });
  }

  // 4) Sondas de vulnerabilidades típicas (rutas que buscan los escáneres).
  if (isProbePath(pathname)) {
    logEvent({
      ...base, category: "ATTACK", severity: "WARNING", statusCode: statusCode || 404,
      attackTypes: ["Sonda de vulnerabilidad (escaneo)"],
      message: `Sonda de escaneo: intento de acceder a ${pathname}`,
    });
  }

  // 5) User-agent de herramienta de escaneo conocida.
  if (isSuspiciousUserAgent(meta.userAgent)) {
    logEvent({
      ...base, category: "ATTACK", severity: "WARNING", statusCode,
      attackTypes: ["Escáner / herramienta automatizada"],
      message: `Herramienta de escaneo detectada: ${meta.client}`,
    });
  }
}

// ---------------------------------------------------------------------------
// API de administración: /api/admin/logs (GET = listar, DELETE = vaciar)
// Protegida con el header "x-admin-key" (lo envía admin.html).
// ---------------------------------------------------------------------------
function sendJson(res, status, obj) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8" });
  res.end(JSON.stringify(obj));
}

function handleAdminApi(req, res) {
  const meta = getRequestMeta(req);

  if (req.headers["x-admin-key"] !== ADMIN_PASSWORD) {
    // Dejamos rastro del intento de acceso con clave incorrecta o ausente.
    logEvent({
      ...meta, category: "AUTHZ", severity: "WARNING",
      method: req.method, resource: "/api/admin/logs", statusCode: 401,
      message: "Intento de acceso al panel de logs sin clave válida",
    });
    return sendJson(res, 401, { error: "No autorizado" });
  }

  if (req.method === "GET") {
    // Más recientes primero (igual que getSecurityLogs del módulo original).
    return sendJson(res, 200, { logs: readLogs().reverse() });
  }

  if (req.method === "DELETE") {
    writeLogs([]);
    // El borrado nunca es silencioso: queda registrado quién limpió los logs.
    logEvent({
      ...meta, category: "ADMIN", severity: "WARNING",
      method: "DELETE", resource: "/api/admin/logs", statusCode: 200,
      message: "Se borraron todos los logs de seguridad desde el panel",
    });
    return sendJson(res, 200, { ok: true });
  }

  return sendJson(res, 405, { error: "Método no permitido" });
}

// ---------------------------------------------------------------------------
// Servidor de archivos estáticos
// ---------------------------------------------------------------------------
const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".txt": "text/plain; charset=utf-8",
  ".pdf": "application/pdf",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
};

function send404(res) {
  res.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
  res.end("<h1>404</h1><p>Recurso no encontrado.</p>");
}

function serveFile(res, filePath) {
  try {
    if (!existsSync(filePath) || !statSync(filePath).isFile()) return send404(res);
    const type = MIME[extname(filePath).toLowerCase()] || "application/octet-stream";
    res.writeHead(200, { "Content-Type": type });
    res.end(readFileSync(filePath));
  } catch {
    res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Error interno del servidor");
  }
}

function serveStatic(res, pathname) {
  // Nunca servimos archivos/carpetas ocultos (.data, .git...) ni el servidor.
  const segments = pathname.split("/").filter(Boolean);
  if (segments.some((s) => s.startsWith("."))) return send404(res);
  if (pathname === "/server.mjs") return send404(res);

  let filePath = resolve(join(ROOT, ...segments));
  // Protección contra path traversal: el archivo debe quedar DENTRO de ROOT.
  if (filePath !== ROOT && !filePath.startsWith(ROOT + "\\") && !filePath.startsWith(ROOT + "/")) {
    return send404(res);
  }

  if (existsSync(filePath) && statSync(filePath).isDirectory()) {
    filePath = join(filePath, "index.html");
  }
  serveFile(res, filePath);
}

// ---------------------------------------------------------------------------
// Arranque
// ---------------------------------------------------------------------------
createServer((req, res) => {
  // IP real de la máquina que se conecta (extremo del socket TCP).
  const remoteAddress = req.socket.remoteAddress || "";
  if (remoteAddress && !req.headers["x-forwarded-for"]) {
    req.headers["x-forwarded-for"] = remoteAddress;
  }

  // Cuando la respuesta termina ya conocemos el código de estado: registramos.
  res.on("finish", () => {
    try {
      logTraffic(req, res.statusCode);
    } catch {
      // Nunca dejamos que un fallo de log afecte la petición.
    }
  });

  let pathname = (req.url || "/").split("?")[0];
  try {
    pathname = decodeURIComponent(pathname);
  } catch {
    // Ruta mal codificada: se procesa tal cual (y el 404 quedará logueado).
  }

  if (pathname === "/api/admin/logs") return handleAdminApi(req, res);
  if (pathname === "/admin" || pathname === "/admin.html") {
    return serveFile(res, join(ROOT, "admin.html"));
  }
  serveStatic(res, pathname);
}).listen(PORT, HOST, () => {
  console.log("> Sitio + logs de seguridad escuchando en:");
  console.log(`  - Sitio:  http://localhost:${PORT}`);
  console.log(`  - Panel:  http://localhost:${PORT}/admin`);
  console.log(`  - Red:    http://<IP-DE-ESTA-MAQUINA>:${PORT}`);
  if (ADMIN_PASSWORD === "admin123") {
    console.log('  ⚠ Contraseña del panel por defecto ("admin123"). Define ADMIN_PASSWORD para cambiarla.');
  }
});
