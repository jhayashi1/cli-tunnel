#!/usr/bin/env node

/**
 * cli-tunnel — Tunnel any CLI app to your phone
 *
 * Usage:
 *   cli-tunnel <command> [args...]              # local only
 *   cli-tunnel --tunnel <command> [args...]      # with devtunnel remote access
 *   cli-tunnel --tunnel --name myapp <command>   # named session
 *
 * Examples:
 *   cli-tunnel copilot --yolo
 *   cli-tunnel --tunnel copilot --yolo
 *   cli-tunnel --tunnel --name wizard copilot --agent squad
 *   cli-tunnel --tunnel python -i
 *   cli-tunnel --tunnel --port 4000 node server.js
 */

import {execFileSync, execSync, spawn} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import {fileURLToPath} from 'node:url';
import {WebSocket, WebSocketServer} from 'ws';

import {redactSecrets} from './redact.js';

// ─── Constants ──────────────────────────────────────────────
const REPLAY_BUFFER_MAX_BYTES = 262144; // 256 KB rolling replay buffer
const WS_HEARTBEAT_INTERVAL_MS = 120000; // 2 min — long enough for phone backgrounding
const RATE_LIMIT_WINDOW_MS = 60000; // 1 minute sliding window
const WS_MESSAGE_RATE_LIMIT = 100; // max WS messages per second per connection
const API_RATE_LIMIT = 30; // max API requests per window per IP
const TICKET_RATE_LIMIT = 10; // max ticket requests per window per IP
const PER_IP_WS_CAP = 2; // max simultaneous WS connections from one IP
const PTY_MIN_COLS = 20;
const PTY_MAX_COLS = 500;
const PTY_MIN_ROWS = 5;
const PTY_MAX_ROWS = 200;
const DEFAULT_COLS = 120;
const DEFAULT_ROWS = 30;
const TICKET_EXPIRY_MS = 60000; // ticket valid for 1 minute
const TICKET_GC_INTERVAL_MS = 30000;
const SESSION_CACHE_TTL_MS = 5000; // cache readLocalSessions() for 5s
const DEVTUNNEL_TIMEOUT_MS = 10000;
const TUNNEL_HOST_TIMEOUT_MS = 15000;
const FETCH_TIMEOUT_MS = 3000;
const EARLY_EXIT_CHECK_MS = 2000;

interface DevtunnelTunnel {
    hostConnections?: number;
    labels?: string[];
    tunnelId?: string;
}

// ─── Extended WebSocket interface ───────────────────────────
interface ExtendedWebSocket extends WebSocket {
    _isAlive?: boolean;
    _remoteAddress?: string;
}

// ─── Response types ─────────────────────────────────────────
interface TicketResponse {
    expires?: number;
    ticket: string;
}

// ─── Security headers applied to all API/static responses ───
const SECURITY_HEADERS: Record<string, string> = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options'       : 'DENY',
};

const runDevtunnel = (args: string[], options?: { timeout?: number }): string => {
    return execFileSync('devtunnel', args, {
        encoding: 'utf-8',
        env     : getSubprocessEnv(),
        stdio   : ['pipe', 'pipe', 'pipe'],
        timeout : options?.timeout ?? DEVTUNNEL_TIMEOUT_MS,
    });
};

// ─── Helper functions ───────────────────────────────────────
const sendJsonResponse = (res: http.ServerResponse, statusCode: number, body: Record<string, unknown>, extraHeaders?: Record<string, string>): void => {
    res.writeHead(statusCode, {'Content-Type': 'application/json', ...SECURITY_HEADERS, ...extraHeaders});
    res.end(JSON.stringify(body));
};

// F-15: Global error handlers to prevent unclean crashes
process.on('uncaughtException', (err) => {
    console.error('[fatal] Uncaught exception:', err.message);
    process.exit(1);
});
process.on('unhandledRejection', (reason) => {
    console.error('[fatal] Unhandled rejection:', reason);
    process.exit(1);
});

const askUser = async (question: string): Promise<string> => {
    const rl = readline.createInterface({input: process.stdin, output: process.stdout});
    return await new Promise((resolve) => {
        rl.question(question, (answer) => { rl.close(); resolve(answer.trim().toLowerCase()); });
    });
};

const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';

// ─── Parse args ─────────────────────────────────────────────
const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
    console.log(`
${BOLD}cli-tunnel${RESET} — Tunnel any CLI app to your phone

${BOLD}Usage:${RESET}
  cli-tunnel [options] <command> [args...]
  cli-tunnel                              # hub mode — sessions dashboard only

${BOLD}Options:${RESET}
  --local            Disable devtunnel (localhost only)
  --anon, -a         Allow anonymous access to the tunnel (no devtunnel login required)
  --max-users <n>    Max simultaneous WebSocket connections (default: 5)
  --port <n>         Bridge port (default: random)
  --name <name>      Session name (shown in dashboard)
  --experimental-resizing  Allow remote clients to resize the PTY
  --replay           (deprecated, screen buffer is always on)
  --help, -h         Show this help

${BOLD}Examples:${RESET}
  cli-tunnel copilot --yolo               # tunnel + run copilot
  cli-tunnel copilot --model claude-sonnet-4 --agent squad
  cli-tunnel k9s                          # tunnel + run k9s
  cli-tunnel python -i                    # tunnel + run python
  cli-tunnel --name wizard copilot        # named session
  cli-tunnel --local copilot --yolo       # localhost only, no devtunnel
  cli-tunnel                              # hub: see all active sessions

Devtunnel is enabled by default. All flags after the command name
pass through to the underlying app. cli-tunnel's own flags
(--local, --port, --name) must come before the command.
`);
    process.exit(0);
}

const hasLocal = args.includes('--local');
const hasTunnel = !hasLocal;
const anonMode = args.includes('--anon') || args.includes('-a');
const noWait = args.includes('--no-wait');
const experimentalResizing = args.includes('--experimental-resizing');
const portIdx = args.indexOf('--port');
const port = (portIdx !== -1 && args[portIdx + 1]) ? parseInt(args[portIdx + 1]!, 10) : 0;
const nameIdx = args.indexOf('--name');
const sessionName = (nameIdx !== -1 && args[nameIdx + 1]) ? args[nameIdx + 1]! : '';
const maxUsersIdx = args.indexOf('--max-users');
const maxUsers = (maxUsersIdx !== -1 && args[maxUsersIdx + 1]) ? parseInt(args[maxUsersIdx + 1]!, 10) : 5;

// Everything that's not our flags is the command
const flagsWithValue = new Set(['--max-users', '--name', '--port']);
const booleanFlags = new Set(['--anon', '--experimental-resizing', '--local', '--no-replay', '--no-wait', '--tunnel', '-a']);
const cmdArgs: string[] = [];
let skip = false;
for (let i = 0; i < args.length; i++) {
    if (skip) { skip = false; continue; }
    if (flagsWithValue.has(args[i]!)) { skip = true; continue; }
    if (booleanFlags.has(args[i]!)) continue;
    cmdArgs.push(args[i]!);
}

// Hub mode — no command, just show sessions dashboard
const hubMode = cmdArgs.length === 0;

const command = hubMode ? '' : cmdArgs[0]!;
const commandArgs = hubMode ? [] : cmdArgs.slice(1);
const cwd = process.cwd();

// npm strips execute permissions from prebuilt binaries during publish/install.
// node-pty's spawn-helper must be executable for posix_spawnp to succeed.
const ensureSpawnHelperExecutable = (): void => {
    if (process.platform === 'win32') return;
    try {
        const ptyPkg = import.meta.resolve('node-pty/package.json');
        const ptyDir = path.dirname(fileURLToPath(ptyPkg));
        const helperPath = path.join(ptyDir, 'prebuilds', `${process.platform}-${process.arch}`, 'spawn-helper');
        const stat = fs.statSync(helperPath);
        if (!(stat.mode & 0o111)) {
            fs.chmodSync(helperPath, stat.mode | 0o755);
        }
    } catch { /* best-effort — if it fails, node-pty's own error will surface */ }
};

const getGitInfo = (): { branch: string; repo: string; } => {
    try {
        const remote = execSync('git remote get-url origin', {cwd, encoding: 'utf-8', env: getSubprocessEnv(), stdio: ['pipe', 'pipe', 'pipe']}).trim();
        const repo = remote.split('/').pop()?.replace('.git', '') ?? 'unknown';
        const branch = execSync('git branch --show-current', {cwd, encoding: 'utf-8', env: getSubprocessEnv(), stdio: ['pipe', 'pipe', 'pipe']}).trim() ?? 'unknown';
        return {branch, repo};
    } catch {
        return {branch: 'unknown', repo: path.basename(cwd)};
    }
};

// F-07: Minimal env for subprocess calls (git, devtunnel) — only PATH and essentials
const getSubprocessEnv = (): Record<string, string> => {
    const safe: Record<string, string> = {};
    const allow = ['PATH', 'PATHEXT', 'HOME', 'USERPROFILE', 'TEMP', 'TMP', 'TMPDIR', 'SHELL', 'COMSPEC',
        'SYSTEMROOT', 'WINDIR', 'PROGRAMFILES', 'PROGRAMFILES(X86)', 'APPDATA', 'LOCALAPPDATA',
        'LANG', 'LC_ALL', 'TERM'];
    for (const k of allow) { if (process.env[k]) safe[k] = process.env[k]!; }
    return safe;
};

// ─── Tunnel helpers ─────────────────────────────────────────
const sanitizeLabel = (l: string): string => {
    const clean = l.replace(/[^a-zA-Z0-9_\-=]/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '').substring(0, 50);
    return clean || 'unknown';
};

// ─── Security: Session token for WebSocket auth ────────────
const sessionToken = crypto.randomUUID();

// ─── Session file registry (IPC via filesystem) ────────────
const sessionsDir = path.join(os.homedir(), '.cli-tunnel', 'sessions');
fs.mkdirSync(sessionsDir, {mode: 0o700, recursive: true});
let sessionFilePath: null | string = null;

interface LocalSession { hubMode: boolean; name: string; port: number; token: string; tunnelId: string; tunnelUrl: string; }

const removeSessionFile = (): void => {
    if (sessionFilePath) { try { fs.unlinkSync(sessionFilePath); } catch { /* no-op */ } }
};

const writeSessionFile = (tunnelId: string, tunnelUrl: string, port: number): void => {
    sessionFilePath = path.join(sessionsDir, `${tunnelId}.json`);
    const data = JSON.stringify({
        createdAt: new Date().toISOString(), hubMode,
        machine  : os.hostname(), name     : sessionName || command, pid      : process.pid, port,
        token    : sessionToken, tunnelId,
        tunnelUrl,
    });
    fs.writeFileSync(sessionFilePath, data, {mode: 0o600});
};
let sessionCache: null | { data: LocalSession[]; expiry: number } = null;

const readLocalSessions = (): LocalSession[] => {
    if (sessionCache && sessionCache.expiry > Date.now()) return sessionCache.data;
    try {
        const result = fs.readdirSync(sessionsDir)
            .filter(f => f.endsWith('.json'))
            .map(f => { try { return JSON.parse(fs.readFileSync(path.join(sessionsDir, f), 'utf-8')); } catch { return null; } })
            .filter((s): s is LocalSession => s !== null && !s.hubMode);
        sessionCache = {data: result, expiry: Date.now() + SESSION_CACHE_TTL_MS};
        return result;
    } catch { return []; }
};

// ─── F-18: Session TTL (4 hours) ───────────────────────────
const SESSION_TTL = 4 * 60 * 60 * 1000; // 4 hours
const sessionCreatedAt = Date.now();

// ─── F-02: One-time ticket store for WebSocket auth ────────
const tickets = new Map<string, { expires: number }>();

// #30: Ticket GC — clean expired tickets every 30s
setInterval(() => {
    const now = Date.now();
    for (const [id, t] of tickets) {
        if (t.expires < now) tickets.delete(id);
    }
}, TICKET_GC_INTERVAL_MS);

// ─── Security: Redact secrets from replay events ────────────

// ─── Bridge server ──────────────────────────────────────────
const connections = new Map<string, WebSocket>();
// Hub relay: WS connections from hub to local sessions (for grid view)
const relayConnections = new Map<number, WebSocket>(); // port → ws to session
let _localResizeAt = 0; // Timestamp of last local terminal resize

// #10: Session TTL enforcement — periodically close expired connections
setInterval(() => {
    if (Date.now() - sessionCreatedAt > SESSION_TTL) {
        for (const [id, ws] of connections) {
            ws.close(1000, 'Session expired');
            connections.delete(id);
        }
    }
}, RATE_LIMIT_WINDOW_MS);

// ─── F-8: Per-IP rate limiter ───────────────────────────────
const rateLimits = new Map<string, { count: number; resetAt: number }>();
const ticketRateLimits = new Map<string, { count: number; resetAt: number }>();

const checkRateLimit = (ip: string, map: Map<string, { count: number; resetAt: number }>, maxRequests: number): boolean => {
    const now = Date.now();
    const entry = map.get(ip);
    if (!entry || entry.resetAt < now) {
        map.set(ip, {count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS});
        return true;
    }
    entry.count++;
    return entry.count <= maxRequests;
};

// Clean up rate limit maps every 60s
setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of rateLimits) { if (entry.resetAt < now) rateLimits.delete(ip); }
    for (const [ip, entry] of ticketRateLimits) { if (entry.resetAt < now) ticketRateLimits.delete(ip); }
}, RATE_LIMIT_WINDOW_MS);

const server = http.createServer(async (req, res) => {
    const clientIp = req.socket.remoteAddress ?? 'unknown';

    // F-8: Rate limiting for HTTP endpoints
    if (req.url?.startsWith('/api/')) {
        const isTicket = req.url === '/api/auth/ticket';
        if (isTicket) {
            if (!checkRateLimit(clientIp, ticketRateLimits, TICKET_RATE_LIMIT)) {
                sendJsonResponse(res, 429, {error: 'Too Many Requests'});
                return;
            }
        } else {
            if (!checkRateLimit(clientIp, rateLimits, API_RATE_LIMIT)) {
                sendJsonResponse(res, 429, {error: 'Too Many Requests'});
                return;
            }
        }
    }
    // F-18: Session expiry check for API routes
    if (!hubMode && req.url?.startsWith('/api/') && Date.now() - sessionCreatedAt > SESSION_TTL) {
        sendJsonResponse(res, 401, {error: 'Session expired'});
        return;
    }

    // F-02: Ticket endpoint — exchange session token for one-time WS ticket
    if (req.url === '/api/auth/ticket' && req.method === 'POST') {
        const auth = req.headers.authorization?.replace('Bearer ', '');
        if (auth !== sessionToken) { res.writeHead(401); res.end(); return; }
        const ticket = crypto.randomUUID();
        const expiresAt = Date.now() + TICKET_EXPIRY_MS;
        tickets.set(ticket, {expires: expiresAt});
        sendJsonResponse(res, 200, {expires: expiresAt, ticket});
        return;
    }

    // F-01: Session token check for all API routes
    if (req.url?.startsWith('/api/')) {
        const reqUrl = new URL(req.url, `http://${req.headers.host}`);
        const authToken = req.headers.authorization?.replace('Bearer ', '') ?? reqUrl.searchParams.get('token');
        if (authToken !== sessionToken) {
            sendJsonResponse(res, 401, {error: 'Unauthorized'});
            return;
        }
    }

    // Hub ticket proxy — fetch ticket from local session on behalf of grid client
    // F-03: Only hub mode sessions can use this endpoint (hub token already validated above)
    if (hubMode && req.url?.startsWith('/api/proxy/ticket/') && req.method === 'POST') {
        const ticketPathMatch = req.url?.match(/^\/api\/proxy\/ticket\/(\d+)$/);
        if (!ticketPathMatch) { sendJsonResponse(res, 400, {error: 'Invalid port'}); return; }
        const targetPort = parseInt(ticketPathMatch[1], 10);
        if (!Number.isFinite(targetPort) || targetPort < 1 || targetPort > 65535) {
            sendJsonResponse(res, 400, {error: 'Invalid port'}); return;
        }
        // Find token for this port from session files
        const localSessions = readLocalSessions();
        const session = localSessions.find(s => s.port === targetPort);
        if (!session) { sendJsonResponse(res, 404, {error: 'Session not found'}); return; }
        try {
            const ticketResp = await fetch(`http://127.0.0.1:${targetPort}/api/auth/ticket`, {
                headers: {Authorization: `Bearer ${session.token}`}, method : 'POST',
                signal : AbortSignal.timeout(FETCH_TIMEOUT_MS),
            });
            if (!ticketResp.ok) throw new Error('Ticket request failed');
            const ticketData = await ticketResp.json() as TicketResponse;
            sendJsonResponse(res, 200, {port: targetPort, ticket: ticketData.ticket});
        } catch {
            sendJsonResponse(res, 502, {error: 'Session unreachable'}); return;
        }
        return;
    }

    // Sessions API
    if ((req.url === '/api/sessions' || req.url?.startsWith('/api/sessions?')) && req.method === 'GET') {
        try {
            const output = runDevtunnel(['list', '--labels', 'cli-tunnel', '--json']);
            const data = JSON.parse(output);
            const localMachine = os.hostname();
            const localSessions = hubMode ? readLocalSessions() : [];
            const tokenMap = new Map(localSessions.map(s => [s.tunnelId, s.token]));

            const sessions = (data.tunnels ?? []).map((t: DevtunnelTunnel & Record<string, unknown>) => {
                const labels = (t.labels ?? []) as string[];
                const id = (t.tunnelId ?? '').replace(/\.\w+$/, '') ?? t.tunnelId;
                const cluster = (t.tunnelId ?? '').split('.').pop() ?? 'euw';
                const portLabel = labels.find((l: string) => l.startsWith('port-'));
                const p = portLabel ? parseInt(portLabel.replace('port-', ''), 10) : 3456;
                const machine = labels[4] ?? 'unknown';
                const session: Record<string, unknown> = {
                    branch  : (labels[3] ?? 'unknown').replace(/_/g, '/'), id,
                    isLocal : machine === localMachine,
                    machine,
                    name    : labels[1] ?? 'unnamed',
                    online  : (t.hostConnections ?? 0) > 0,
                    port    : p,
                    repo    : labels[2] ?? 'unknown',
                    tunnelId: t.tunnelId,
                    url     : `https://${id}-${p}.${cluster}.devtunnels.ms`,
                };
                // F-05: Never expose raw tokens in API responses — only indicate availability
                const baseId = (t.tunnelId ?? '').split('.')[0] ?? t.tunnelId;
                const token = tokenMap.get(baseId as string) ?? tokenMap.get(t.tunnelId as string);
                if (token) session.hasToken = true;
                return session;
            });
            sendJsonResponse(res, 200, {sessions});
        } catch {
            sendJsonResponse(res, 200, {sessions: []});
        }
        return;
    }

    // Delete session
    // F-05: Only allow deleting tunnels owned by this machine
    if (req.url?.startsWith('/api/sessions/') && req.method === 'DELETE') {
        const tunnelId = req.url.replace('/api/sessions/', '').replace(/\.\w+$/, '');
        if (!/^[a-zA-Z0-9._-]+$/.test(tunnelId)) {
            sendJsonResponse(res, 400, {error: 'Invalid tunnel ID'});
            return;
        }
        // Verify the tunnel belongs to this machine before allowing delete
        try {
            const verifyOut = runDevtunnel(['show', tunnelId, '--json']);
            const verifyData = JSON.parse(verifyOut);
            const labels = verifyData.tunnel?.labels ?? [];
            const tunnelMachine = labels[4] ?? '';
            if (tunnelMachine !== os.hostname()) {
                sendJsonResponse(res, 403, {error: 'Cannot delete tunnels from other machines'});
                return;
            }
        } catch {
            sendJsonResponse(res, 403, {error: 'Cannot verify tunnel ownership'});
            return;
        }
        try {
            runDevtunnel(['delete', tunnelId, '--force']);
            sendJsonResponse(res, 200, {deleted: true});
        } catch {
            sendJsonResponse(res, 200, {deleted: false});
        }
        return;
    }

    // Static files
    const uiDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../remote-ui');
    // #18: Guard against malformed URI encoding
    let decodedUrl: string;
    try {
    // Strip query string before resolving file path
        const urlPath = (req.url ?? '/').split('?')[0]!;
        decodedUrl = decodeURIComponent(urlPath);
    } catch {
        res.writeHead(400); res.end(); return;
    }
    if (decodedUrl.includes('..')) { res.writeHead(400); res.end(); return; }
    let filePath = path.resolve(uiDir, decodedUrl === '/' ? 'index.html' : decodedUrl.replace(/^\//, ''));
    if (!filePath.startsWith(uiDir)) { res.writeHead(403); res.end(); return; }
    // #2: EISDIR guard — check if path is a directory before createReadStream
    try {
        const stat = fs.statSync(filePath);
        if (stat.isDirectory()) {
            filePath = path.join(filePath, 'index.html');
            if (!fs.existsSync(filePath)) { res.writeHead(404); res.end(); return; }
        }
    } catch { res.writeHead(404); res.end(); return; }
    const ext = path.extname(filePath);
    const mimes: Record<string, string> = {'.css': 'text/css', '.html': 'text/html', '.js': 'application/javascript', '.json': 'application/json'};
    const securityHeaders: Record<string, string> = {
        'Cache-Control'            : 'no-store',
        'Content-Security-Policy'  : 'default-src \'self\'; script-src \'self\' https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/ https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/; style-src \'self\' \'unsafe-inline\' https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/ https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/; connect-src \'self\' ws://localhost:* ws://127.0.0.1:* wss://*.devtunnels.ms https://*.devtunnels.ms;',
        'Content-Type'             : mimes[ext] || 'application/octet-stream',
        'Referrer-Policy'          : 'no-referrer',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options'   : 'nosniff',
        'X-Frame-Options'          : 'DENY',
    };
    res.writeHead(200, securityHeaders);
    // #8: Handle createReadStream errors
    const stream = fs.createReadStream(filePath);
    stream.on('error', () => { if (!res.headersSent) { res.writeHead(500); } res.end(); });
    stream.pipe(res);
});

const wss = new WebSocketServer({
    maxPayload  : 1048576,
    server,
    verifyClient: (info: { req: http.IncomingMessage }): boolean => {

        // F-18: Session expiry
        if (Date.now() - sessionCreatedAt > SESSION_TTL) return false;
        // F-3: Validate origin when present (devtunnel proxies may strip it)
        const origin = info.req.headers.origin;
        if (origin) {
            try {
                const originUrl = new URL(origin);
                const host = originUrl.hostname;
                if (host !== 'localhost' && host !== '127.0.0.1' && !host.endsWith('.devtunnels.ms')) {
                    return false;
                }
            } catch { return false; }
        }
        const url = new URL(info.req.url!, `http://${info.req.headers.host}`);
        // F-02: Accept one-time ticket (only auth method for WS)
        const ticket = url.searchParams.get('ticket');
        if (ticket && tickets.has(ticket)) {
            const t = tickets.get(ticket)!;
            tickets.delete(ticket);
            return t.expires > Date.now();
        }
        return false;
    },
});

// ─── Security: Audit log for remote PTY input ──────────────
const auditDir = path.join(os.homedir(), '.cli-tunnel', 'audit');
fs.mkdirSync(auditDir, {mode: 0o700, recursive: true});
const auditLogPath = path.join(auditDir, `audit-${new Date().toISOString().slice(0, 10)}.jsonl`);
const auditLog = fs.createWriteStream(auditLogPath, {flags: 'a', mode: 0o600});
auditLog.on('error', (err) => { console.error('Audit log error:', err.message); });

// R-01: WebSocketServer error handler — prevents process crash on WSS-level errors
wss.on('error', (err) => {
    console.error('[wss] WebSocketServer error:', err.message);
});

wss.on('connection', (ws, req) => {
    // F-10: Connection cap (global + per-IP)
    if (connections.size >= maxUsers) {
        ws.close(1013, 'Max connections reached');
        return;
    }
    const remoteAddress = req.socket.remoteAddress ?? 'unknown';
    let perIpCount = 0;
    for (const [, c] of connections) {
        if ((c as ExtendedWebSocket)._remoteAddress === remoteAddress) perIpCount++;
    }
    if (perIpCount >= PER_IP_WS_CAP) {
        ws.close(1013, 'Max connections per IP reached');
        return;
    }
    const id = crypto.randomUUID();
    (ws as ExtendedWebSocket)._remoteAddress = remoteAddress;
    connections.set(id, ws);

    // R-02: Per-connection error handler to prevent unhandled crash
    ws.on('error', (err) => { console.error('[ws] Connection error:', err.message); });

    // Send replay buffer to late-joining clients (catch up on PTY state)
    if (!hubMode && replayBuffer.length > 0) {
        ws.send(JSON.stringify({data: replayBuffer, type: 'pty'}));
    }

    // F-13: Per-connection WS message rate limiter (100 msg/sec)
    let wsMessageCount = 0;
    let wsMessageResetAt = Date.now() + 1000;

    // F-10: WS ping/pong heartbeat
    (ws as ExtendedWebSocket)._isAlive = true;
    ws.on('pong', () => { (ws as ExtendedWebSocket)._isAlive = true; });

    ws.on('message', async (data) => {
    // F-13: Enforce WS message rate limit (100 msg/sec)
        const now = Date.now();
        if (now > wsMessageResetAt) { wsMessageCount = 0; wsMessageResetAt = now + 1000; }
        wsMessageCount++;
        if (wsMessageCount > WS_MESSAGE_RATE_LIMIT) {
            auditLog.write(`${JSON.stringify({reason: 'ws-rate-limit', src: remoteAddress, ts: new Date().toISOString(), type: 'rejected'}) }\n`);
            return;
        }
        const raw = data.toString();
        try {
            const msg = JSON.parse(raw);
            if (msg.type === 'pty_input' && ptyProcess) {
                // R-03: Validate msg.data is a string before writing to PTY
                if (typeof msg.data !== 'string') {
                    auditLog.write(`${JSON.stringify({dataType: typeof msg.data, reason: 'invalid-data-type', src: remoteAddress, ts: new Date().toISOString(), type: 'rejected'}) }\n`);
                } else {
                    auditLog.write(`${JSON.stringify({data: redactSecrets(msg.data), src: remoteAddress, ts: new Date().toISOString(), type: 'pty_input'}) }\n`);
                    ptyProcess.write(msg.data);
                }
            }
            // Resize PTY to match the browser's terminal dimensions so rendering is aligned
            if (msg.type === 'pty_resize' && ptyProcess && experimentalResizing) {
                const c = Math.max(PTY_MIN_COLS, Math.min(PTY_MAX_COLS, Math.floor(Number(msg.cols))));
                const r = Math.max(PTY_MIN_ROWS, Math.min(PTY_MAX_ROWS, Math.floor(Number(msg.rows))));
                if (c > 0 && r > 0) ptyProcess.resize(c, r);
            }
            // Grid relay: hub proxies PTY data between phone and local sessions
            if (hubMode && msg.type === 'grid_connect') {
                const port = Number(msg.port);
                if (!Number.isFinite(port) || port < 1 || port > 65535) return;

                const localSessions = readLocalSessions();
                const session = localSessions.find(s => s.port === port);
                if (!session) return;

                try {
                    const ticketResp = await fetch(`http://127.0.0.1:${port}/api/auth/ticket`, {
                        headers: {Authorization: `Bearer ${session.token}`},
                        method : 'POST',
                        signal : AbortSignal.timeout(FETCH_TIMEOUT_MS),
                    });
                    if (!ticketResp.ok) return;
                    const {ticket} = await ticketResp.json() as TicketResponse;

                    const sessionWs = new WebSocket(`ws://127.0.0.1:${port}?ticket=${encodeURIComponent(ticket)}`, {
                        headers: {origin: `http://127.0.0.1:${port}`},
                    });

                    sessionWs.on('open', () => {
                        relayConnections.set(port, sessionWs);
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({port, type: 'grid_connected'}));
                        }
                    });

                    sessionWs.on('message', (sData) => {
                        try {
                            const parsed = JSON.parse(sData.toString());
                            if (parsed.type === 'pty' && ws.readyState === WebSocket.OPEN) {
                                ws.send(JSON.stringify({data: parsed.data, port, type: 'grid_pty'}));
                            }
                        } catch (err) {
                            console.error('[grid] Relay message parse error:', (err as Error).message);
                        }
                    });

                    sessionWs.on('close', () => {
                        relayConnections.delete(port);
                        if (ws.readyState === WebSocket.OPEN) {
                            ws.send(JSON.stringify({port, type: 'grid_disconnected'}));
                        }
                    });

                    sessionWs.on('error', (err) => {
                        console.error('[grid] Relay connection error:', (err as Error).message);
                        relayConnections.delete(port);
                    });
                } catch (err) {
                    console.error('[grid] Failed to establish relay:', (err as Error).message);
                }
            }

            if (hubMode && msg.type === 'grid_input') {
                const port = Number(msg.port);
                const relay = relayConnections.get(port);
                if (relay && relay.readyState === WebSocket.OPEN) {
                    relay.send(JSON.stringify({data: msg.data, type: 'pty_input'}));
                }
            }
        } catch {
            // #3: Log but do NOT write to PTY — only structured pty_input messages allowed
            auditLog.write(`${JSON.stringify({length: raw.length, reason: 'non-json', ts: new Date().toISOString(), type: 'rejected'}) }\n`);
        }
    });

    ws.on('close', () => {
        connections.delete(id);
        // Close all relay connections when hub client disconnects
        for (const [_port, relay] of relayConnections) {
            relay.close();
        }
        relayConnections.clear();
    });
});

// F-10: WS heartbeat — ping every 2 minutes, close unresponsive connections
// Longer interval prevents killing phone connections that go to background briefly
setInterval(() => {
    for (const [id, ws] of connections) {
        if ((ws as ExtendedWebSocket)._isAlive === false) {
            ws.terminate();
            connections.delete(id);
            continue;
        }
        (ws as ExtendedWebSocket)._isAlive = false;
        ws.ping();
    }
}, WS_HEARTBEAT_INTERVAL_MS);

// Rolling replay buffer for late-joining clients (grid panels, reconnects)
let replayBuffer = '';

const broadcast = (data: string): void => {
    const redacted = redactSecrets(data);
    const msg = JSON.stringify({data: redacted, type: 'pty'});
    // Append to replay buffer (rolling, max 256KB)
    replayBuffer += redacted;
    if (replayBuffer.length > REPLAY_BUFFER_MAX_BYTES) replayBuffer = replayBuffer.slice(-REPLAY_BUFFER_MAX_BYTES);
    for (const [, ws] of connections) {
        if (ws.readyState === WebSocket.OPEN) ws.send(msg);
    }
};

// ─── Start bridge ───────────────────────────────────────────
let ptyProcess: any = null;

const main = async (): Promise<void> => {
    const actualPort = await new Promise<number>((resolve, reject) => {
        server.listen(port, '127.0.0.1', () => {
            const addr = server.address();
            resolve(typeof addr === 'object' ? addr!.port : port);
        });
        server.on('error', reject);
    });

    const {branch, repo} = getGitInfo();
    const machine = os.hostname();
    const displayName = sessionName || command;

    console.log(`\n${BOLD}cli-tunnel${RESET} ${DIM}v1.1.0${RESET}\n`);
    if (hubMode) {
        console.log(`  ${BOLD}📋 Hub Mode${RESET} — sessions dashboard`);
        console.log(`  ${DIM}Port:${RESET}     ${actualPort}`);
        console.log(`  ${DIM}Local URL:${RESET} http://127.0.0.1:${actualPort}?token=${sessionToken}&hub=1`);
        console.log(`  ${YELLOW}⚠ Token in URL — do not share this URL in screen recordings or public channels${RESET}\n`);
    } else {
        console.log(`  ${DIM}Command:${RESET}  ${command} ${commandArgs.join(' ')}`);
        console.log(`  ${DIM}Name:${RESET}     ${displayName}`);
        console.log(`  ${DIM}Port:${RESET}     ${actualPort}`);
        console.log(`  ${DIM}Audit log:${RESET} ${auditLogPath}`);
        console.log(`  ${DIM}Local URL:${RESET} http://127.0.0.1:${actualPort}?token=${sessionToken}`);
        console.log(`  ${YELLOW}⚠ Token in URL — do not share this URL in screen recordings or public channels${RESET}`);
        console.log(`  ${DIM}Session expires:${RESET} ${new Date(sessionCreatedAt + SESSION_TTL).toLocaleTimeString()}`);
    }

    // Tunnel
    if (hasTunnel) {
    // Check if devtunnel is installed
        let devtunnelInstalled = false;
        try {
            execFileSync('devtunnel', ['--version'], {env: getSubprocessEnv(), stdio: 'pipe'});
            devtunnelInstalled = true;
        } catch {
            console.log(`\n  ${YELLOW}⚠ devtunnel CLI not found!${RESET}\n`);
            let installCmd: string;
            if (process.platform === 'win32') {
                installCmd = 'winget install Microsoft.devtunnel';
            } else if (process.platform === 'darwin') {
                installCmd = 'brew install --cask devtunnel';
            } else {
                installCmd = 'curl -sL https://aka.ms/DevTunnelCliInstall | bash';
            }
            const answer = await askUser(`  Would you like to install it now? (${GREEN}${installCmd}${RESET}) [Y/n] `);
            if (answer === '' || answer === 'y' || answer === 'yes') {
                console.log(`\n  ${DIM}Installing devtunnel...${RESET}\n`);
                try {
                    const installParts = installCmd.split(' ');
                    const installProc = spawn(installParts[0]!, installParts.slice(1), {env: getSubprocessEnv(), shell: process.platform !== 'win32' && installCmd.includes('|'), stdio: 'inherit'});
                    await new Promise<void>((resolve, reject) => {
                        installProc.on('close', (code) => code === 0 ? resolve() : reject(new Error(`Install exited with code ${code}`)));
                        installProc.on('error', reject);
                    });
                    // Refresh PATH — winget updates the registry but current process has stale PATH
                    if (process.platform === 'win32') {
                        try {
                            const userPath = execFileSync('reg', ['query', 'HKCU\\Environment', '/v', 'Path'], {encoding: 'utf-8', env: getSubprocessEnv(), stdio: ['pipe', 'pipe', 'pipe']});
                            const sysPath = execFileSync('reg', ['query', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment', '/v', 'Path'], {encoding: 'utf-8', env: getSubprocessEnv(), stdio: ['pipe', 'pipe', 'pipe']});
                            const extractPath = (out: string): string => out.split('\n').find(l => l.includes('REG_'))?.split('REG_EXPAND_SZ')[1]?.trim() ?? out.split('\n').find(l => l.includes('REG_'))?.split('REG_SZ')[1]?.trim() ?? '';
                            process.env.PATH = `${extractPath(userPath)};${extractPath(sysPath)}`;
                        } catch { /* keep existing PATH */ }
                    }
                    // Verify installation
                    execFileSync('devtunnel', ['--version'], {env: getSubprocessEnv(), stdio: 'pipe'});
                    console.log(`\n  ${GREEN}✓${RESET} devtunnel installed successfully!\n`);
                    devtunnelInstalled = true;
                } catch (err) {
                    console.log(`\n  ${YELLOW}⚠${RESET} Installation failed: ${(err as Error).message}`);
                    console.log(`  ${DIM}You can install it manually: ${installCmd}${RESET}\n`);
                    console.log(`  ${DIM}Continuing without tunnel (local only)...${RESET}\n`);
                }
            } else {
                console.log(`\n  ${DIM}More info: https://aka.ms/devtunnels/doc${RESET}`);
                console.log(`  ${DIM}Continuing without tunnel (local only)...${RESET}\n`);
            }
        }

        if (devtunnelInstalled) {
            // Check if logged in before attempting tunnel creation (skip in anon mode)
            if (!anonMode) {
                try {
                    const userInfo = execFileSync('devtunnel', ['user', 'show'], {encoding: 'utf-8', env: getSubprocessEnv(), stdio: ['pipe', 'pipe', 'pipe']});
                    if (userInfo.includes('not logged in') || userInfo.includes('No user') || userInfo.includes('Anonymous')) {
                        throw new Error('not logged in');
                    }
                } catch {
                    console.log(`\n  ${YELLOW}⚠ devtunnel not authenticated.${RESET}\n`);
                    const loginAnswer = await askUser('  Would you like to log in now? [Y/n] ');
                    if (loginAnswer === '' || loginAnswer === 'y' || loginAnswer === 'yes') {
                        try {
                            const loginProc = spawn('devtunnel', ['user', 'login'], {env: getSubprocessEnv(), stdio: 'inherit'});
                            await new Promise<void>((resolve, reject) => {
                                loginProc.on('close', (code) => code === 0 ? resolve() : reject(new Error(`Login exited with code ${code}`)));
                                loginProc.on('error', reject);
                            });
                            console.log(`\n  ${GREEN}✓${RESET} Logged in successfully!\n`);
                        } catch {
                            console.log(`\n  ${YELLOW}⚠${RESET} Login failed. Run manually: ${GREEN}devtunnel user login${RESET}\n`);
                            console.log(`  ${DIM}Continuing without tunnel (local only)...${RESET}\n`);
                            devtunnelInstalled = false;
                        }
                    } else {
                        console.log(`\n  ${DIM}Run this once to log in: ${GREEN}devtunnel user login${RESET}`);
                        console.log(`  ${DIM}Continuing without tunnel (local only)...${RESET}\n`);
                        devtunnelInstalled = false;
                    }
                }
            }
        }

        if (devtunnelInstalled) {
            try {
                const labelValues = ['cli-tunnel', sanitizeLabel(sessionName || command), sanitizeLabel(repo), sanitizeLabel(branch), sanitizeLabel(machine), `port-${actualPort}`];
                const labelArgs = labelValues.flatMap(l => ['--labels', l]);
                const createOut = execFileSync('devtunnel', ['create', ...labelArgs, '--expiration', '1d', ...(anonMode ? ['--allow-anonymous'] : []), '--json'], {encoding: 'utf-8', env: getSubprocessEnv(), stdio: ['pipe', 'pipe', 'pipe']});
                const tunnelId = JSON.parse(createOut).tunnel?.tunnelId?.split('.')[0];
                const _cluster = JSON.parse(createOut).tunnel?.tunnelId?.split('.')[1] ?? 'euw';
                execFileSync('devtunnel', ['port', 'create', tunnelId, '-p', String(actualPort), '--protocol', 'http'], {env: getSubprocessEnv(), stdio: 'pipe'});
                const hostProc = spawn('devtunnel', ['host', tunnelId, ...(anonMode ? ['--allow-anonymous'] : [])], {detached: false, env: getSubprocessEnv(), stdio: 'pipe'});

                const url = await new Promise<string>((resolve, reject) => {
                    const timeout = setTimeout(() => reject(new Error('Tunnel timeout')), TUNNEL_HOST_TIMEOUT_MS);
                    let out = '';
                    hostProc.stdout?.on('data', (d: Buffer) => {
                        out += d.toString();
                        const match = out.match(/https:\/\/[^\s]+/);
                        if (match) { clearTimeout(timeout); resolve(match[0]); }
                    });
                    hostProc.on('error', (e) => { clearTimeout(timeout); reject(e); });
                });

                const tunnelUrlWithToken = `${url}?token=${sessionToken}${hubMode ? '&hub=1' : ''}`;
                console.log(`  ${GREEN}✓${RESET} Tunnel: ${BOLD}${tunnelUrlWithToken}${RESET}`);
                console.log(`  ${YELLOW}⚠ Token in URL — do not share in screen recordings or public channels${RESET}\n`);

                // Write session file for hub discovery
                writeSessionFile(tunnelId, url, actualPort);

                try {
                    // @ts-ignore
                    const qr = (await import('qrcode-terminal')) as any;
                    const qrModule = qr.default ?? qr;
                    await new Promise<void>((resolve) => {
                        qrModule.generate(tunnelUrlWithToken, {small: true}, (code: string) => { console.log(code); resolve(); });
                    });
                } catch { /* no-op — QR code is optional */ }

                process.on('SIGINT', () => { removeSessionFile(); hostProc.kill(); try { execFileSync('devtunnel', ['delete', tunnelId, '--force'], {env: getSubprocessEnv(), stdio: 'pipe'}); } catch { /* best-effort cleanup */ } });
                process.on('exit', () => { removeSessionFile(); hostProc.kill(); try { execFileSync('devtunnel', ['delete', tunnelId, '--force'], {env: getSubprocessEnv(), stdio: 'pipe'}); } catch { /* best-effort cleanup */ } });
            } catch (err) {
                const errMsg = (err as Error).message || '';
                // Detect auth failure at create time (expired token, anonymous, etc.)
                if (errMsg.includes('Anonymous') || errMsg.includes('Unauthorized') || errMsg.includes('not permitted')) {
                    console.log(`\n  ${YELLOW}⚠ devtunnel session expired or not authenticated.${RESET}\n`);
                    const loginAnswer = await askUser('  Would you like to log in now? [Y/n] ');
                    if (loginAnswer === '' || loginAnswer === 'y' || loginAnswer === 'yes') {
                        try {
                            const loginProc = spawn('devtunnel', ['user', 'login'], {env: getSubprocessEnv(), stdio: 'inherit'}); await new Promise<void>((resolve, reject) => {
                                loginProc.on('close', (code) => code === 0 ? resolve() : reject(new Error(`Login exited with code ${code}`)));
                                loginProc.on('error', reject);
                            });
                            console.log(`\n  ${GREEN}✓${RESET} Logged in! Please run cli-tunnel again to create the tunnel.\n`);
                        } catch {
                            console.log(`\n  ${YELLOW}⚠${RESET} Login failed. Run manually: ${GREEN}devtunnel user login${RESET}\n`);
                        }
                    }
                } else {
                    console.log(`  ${YELLOW}⚠${RESET} Tunnel failed: ${errMsg}\n`);
                }
            }
        } // end if (devtunnelInstalled)
    }

    // Write session file for local-only sessions (no tunnel) so hub can discover them
    if (!hasTunnel && !hubMode && !sessionFilePath) {
        const localId = `local-${actualPort}`;
        writeSessionFile(localId, `http://127.0.0.1:${actualPort}`, actualPort);
        process.on('SIGINT', () => { removeSessionFile(); });
        process.on('exit', () => { removeSessionFile(); });
    }

    if (hubMode) {
    // Hub mode — just serve the sessions dashboard, no PTY
        console.log(`  ${GREEN}✓${RESET} Hub running — open in browser to see all sessions\n`);
        console.log(`  ${DIM}Press Ctrl+C to stop.${RESET}\n`);
        process.on('SIGINT', () => { server.close(); process.exit(0); });
        // Keep process alive
        await new Promise(() => {});
    }

    // Wait for user to scan QR / copy URL before starting the CLI tool
    if (hasTunnel && !noWait) {
        console.log(`  ${BOLD}Press any key to start ${command}...${RESET}`);
        await new Promise<void>((resolve) => {
            if (process.stdin.isTTY) process.stdin.setRawMode(true);
            process.stdin.resume();
            process.stdin.once('data', () => resolve());
        });
    // Don't pause or reset raw mode — we'll set it up properly for PTY below
    }

    console.log(`  ${DIM}Starting ${command}...${RESET}\n`);

    // Clear screen before PTY takes over — prevents overlap with banner/QR output
    process.stdout.write('\x1b[2J\x1b[H');

    // Spawn PTY
    const nodePty = await import('node-pty');
    ensureSpawnHelperExecutable();
    const cols = process.stdout.columns || DEFAULT_COLS;
    const rows = process.stdout.rows || DEFAULT_ROWS;
    // Capture original dimensions so we can restore them on exit
    const originalCols = cols;
    const originalRows = rows;

    // Resolve command path for node-pty on Windows
    let resolvedCmd = command;
    if (process.platform === 'win32') {
        try {
            const wherePaths = execFileSync('where', [command], {encoding: 'utf-8', env: getSubprocessEnv(), stdio: ['pipe', 'pipe', 'pipe']}).trim().split('\n');
            // Prefer .exe or .cmd over .ps1 for node-pty compatibility
            const exePath = wherePaths.find(p => p.trim().endsWith('.exe')) ?? wherePaths.find(p => p.trim().endsWith('.cmd'));
            if (exePath) {
                resolvedCmd = exePath.trim();
            } else {
                // For .ps1 scripts, wrap with powershell
                resolvedCmd = 'powershell';
                commandArgs.unshift('-File', wherePaths[0]!.trim());
            }
        } catch { /* use as-is */ }
    }

    // F-07: Security — filter dangerous environment variables for PTY
    // Blocklist approach: pass everything except known dangerous vars and secrets
    const DANGEROUS_VARS = new Set(['_JAVA_OPTIONS', 'ALL_PROXY', 'AWS_SECURITY_TOKEN',
        'AWS_SESSION_TOKEN', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET',
        'AZURE_SUBSCRIPTION_ID', 'AZURE_TENANT_ID', 'BASH_ENV',
        'BASH_FUNC', // F-04: Additional dangerous vars missed by original blocklist
        'DATABASE_URL',
        'DYLD_INSERT_LIBRARIES', 'ENV', 'GCP_SERVICE_ACCOUNT', 'GOOGLE_APPLICATION_CREDENTIALS', 'GPG_TTY', 'HISTFILE', 'HISTFILESIZE',
        'HTTP_PROXY', 'HTTPS_PROXY', 'JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS', 'LD_PRELOAD',
        'LESSHISTFILE', 'MONGO_URL', 'MONGODB_URI', 'NO_PROXY',
        'NODE_EXTRA_CA_CERTS', 'NODE_OPTIONS', 'NODE_PATH',
        'NODE_PENDING_DEPRECATION', 'NODE_REDIRECT_WARNINGS', 'NODE_REPL_HISTORY', 'PERL5OPT',
        'PROMPT_COMMAND', 'PYTHONPATH', 'PYTHONSTARTUP',
        'REDIS_URL', 'RUBYOPT',
        'SENDGRID_API_KEY', 'SLACK_BOT_TOKEN', 'SLACK_TOKEN', 'SLACK_WEBHOOK_URL',
        'SSH_AUTH_SOCK', 'STRIPE_SECRET_KEY', 'TWILIO_AUTH_TOKEN',
        'UV_THREADPOOL_SIZE', 'ZDOTDIR']);
    const sensitivePattern = /token|secret|key|password|credential|api_key|private_key|access_key|connection_string|auth|kubeconfig|docker_host|docker_config|passwd|dsn|webhook/i;

    const safeEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
        if (v !== undefined && !DANGEROUS_VARS.has(k) && !sensitivePattern.test(k)) {
            safeEnv[k] = v;
        }
    }

    ptyProcess = nodePty.spawn(resolvedCmd, commandArgs, {
        cols,
        cwd, env: safeEnv, name: 'xterm-256color',
        rows,
    });

    // Register data handler immediately so no PTY output is lost
    ptyProcess.onData((data: string) => {
        process.stdout.write(data);
        broadcast(data);
    });

    // Detect CSPRNG crash (rare Node.js + PTY issue) and show helpful message
    let earlyExitCode: null | number = null;
    const earlyExitCheck = new Promise<void>((resolve) => {
        ptyProcess.onExit(({exitCode}: { exitCode: number }) => {
            earlyExitCode = exitCode;
            resolve();
        });
        setTimeout(resolve, EARLY_EXIT_CHECK_MS);
    });

    await earlyExitCheck;
    if (earlyExitCode !== null) {
        if (earlyExitCode === 134 || earlyExitCode === 3221226505) {
            const nodeVer = process.version;
            console.log(`  ${YELLOW}⚠${RESET} The command crashed (CSPRNG assertion failure).`);
            console.log(`  This is a known issue with Node.js ${nodeVer} + PTY on Windows.`);
            console.log(`  ${BOLD}Fix:${RESET} Install Node.js 22 LTS: ${GREEN}nvm install 22${RESET} or ${GREEN}winget install OpenJS.NodeJS.LTS${RESET}\n`);
            process.exit(1);
        } else {
            console.log(`\n${DIM}Process exited (code ${earlyExitCode}).${RESET}`);
            server.close();
            process.exit(earlyExitCode);
        }
    }

    ptyProcess.onExit(({exitCode}: { exitCode: number }) => {
        console.log(`\n${DIM}Process exited (code ${exitCode}).${RESET}`);
        ptyProcess = null;
        // Restore the terminal to its original dimensions in case the PTY altered them
        process.stdout.write(`\x1b[8;${originalRows};${originalCols}t`);
        server.close();
        process.exit(exitCode);
    });

    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.on('data', (data: Buffer) => { if (ptyProcess) ptyProcess.write(data.toString()); });
    process.stdout.on('resize', () => { _localResizeAt = Date.now(); const c = process.stdout.columns ?? DEFAULT_COLS; const r = process.stdout.rows ?? DEFAULT_ROWS; if (ptyProcess) ptyProcess.resize(c, r); });
};

main().catch((err) => { console.error(err); process.exit(1); });
