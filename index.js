/**
 * Unipile → GHL Middleware Server
 *
 * Receives webhook events from Unipile (LinkedIn activity),
 * transforms the payload, and forwards it to GHL Inbound Webhook.
 *
 * Node.js >= 18 required
 */

"use strict";

const http = require("http");
const https = require("https");
const crypto = require("crypto");

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION  — always set via environment variables, never hard-code secrets
// ─────────────────────────────────────────────────────────────────────────────
const CONFIG = Object.freeze({
  PORT: parseInt(process.env.PORT ?? "3000", 10),

  /** Your Unipile webhook signing secret — found in Unipile dashboard > Developers */
  UNIPILE_WEBHOOK_SECRET: process.env.UNIPILE_WEBHOOK_SECRET ?? "",

  /** GHL Inbound Webhook URL — paste from GHL Automation > Workflows */
  GHL_WEBHOOK_URL: process.env.GHL_WEBHOOK_URL ?? "",

  /** Maximum accepted request body size (1 MB) */
  MAX_BODY_BYTES: 1_048_576,
});

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────
const UNIPILE_SIGNATURE_HEADER = "x-unipile-signature";
const CONTENT_TYPE_JSON = "application/json";

const EVENT_TYPES = Object.freeze({
  MESSAGE_SENT:              "linkedin.message.sent",
  CONNECTION_REQUEST_SENT:   "linkedin.connection.request.sent",
  CONNECTION_ACCEPTED:       "linkedin.connection.accepted",
  MESSAGE_RECEIVED:          "linkedin.message.received",
  MEETING_BOOKED:            "linkedin.meeting.booked",
});

// ─────────────────────────────────────────────────────────────────────────────
// TYPED HTTP ERROR — clean flow control without instanceof checks everywhere
// ─────────────────────────────────────────────────────────────────────────────
class HttpError extends Error {
  /** @param {number} statusCode @param {string} message */
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// LOGGER — JSON-lines format (compatible with DigitalOcean, Datadog, journald)
// ─────────────────────────────────────────────────────────────────────────────
const log = {
  info:  (msg, meta = {}) => console.log( JSON.stringify({ level: "info",  ts: now(), msg, ...meta })),
  warn:  (msg, meta = {}) => console.warn( JSON.stringify({ level: "warn",  ts: now(), msg, ...meta })),
  error: (msg, meta = {}) => console.error(JSON.stringify({ level: "error", ts: now(), msg, ...meta })),
};
const now = () => new Date().toISOString();

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY: read & size-limit request body
// ─────────────────────────────────────────────────────────────────────────────
/** @param {http.IncomingMessage} req @returns {Promise<Buffer>} */
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let totalBytes = 0;

    req.on("data", (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > CONFIG.MAX_BODY_BYTES) {
        req.destroy();
        return reject(new HttpError(413, "Payload too large"));
      }
      chunks.push(chunk);
    });

    req.on("end",   () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITY: verify Unipile HMAC-SHA256 webhook signature
// Uses timing-safe comparison to prevent timing-oracle attacks.
// ─────────────────────────────────────────────────────────────────────────────
/**
 * @param {Buffer} rawBody
 * @param {string} signatureHeader
 * @param {string} secret
 * @returns {boolean}
 */
function verifySignature(rawBody, signatureHeader, secret) {
  if (!secret || !signatureHeader) return false;

  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");

  // Unipile may send the value prefixed with "sha256="
  const incoming = signatureHeader.startsWith("sha256=")
    ? signatureHeader.slice(7)
    : signatureHeader;

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, "hex"),
      Buffer.from(incoming,  "hex"),
    );
  } catch {
    return false; // buffers differ in length → definitely wrong
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// TRANSFORMER: Unipile event → GHL contact-update payload
//
// GHL Custom Fields you must create first (Settings > Custom Fields):
//   • LI Connections Sent   (Number)
//   • LI Replies            (Number)
//   • LI Meetings Booked    (Number)
//   • LI Last Activity Date (Date)
// ─────────────────────────────────────────────────────────────────────────────
/**
 * @param {object} event  Parsed Unipile webhook body
 * @returns {object|null} GHL payload, or null if event should be silently ignored
 * @throws  {HttpError}
 */
function transformEvent(event) {
  const { event_type, account_id, timestamp, data = {} } = event;

  if (!event_type) {
    throw new HttpError(400, "Missing event_type in webhook payload");
  }

  // ── Contact identification ──────────────────────────────────────────────
  const profile         = data.profile ?? {};
  const contactEmail    = profile.email          ?? null;
  const contactLinkedIn = profile.linkedin_url   ?? data.linkedin_url ?? null;
  const contactName     = profile.full_name      ?? profile.name      ?? "Unknown";

  if (!contactEmail && !contactLinkedIn && contactName === "Unknown") {
    throw new HttpError(422, "Insufficient contact identifiers in Unipile payload");
  }

  // ── Activity counters ───────────────────────────────────────────────────
  const activity = {
    linkedinMsgSent:          0,
    linkedinConnectionsSent:  0,
    linkedinReplies:          0,
    linkedinMeetingsBooked:   0,
  };

  let activityNote = "";

  switch (event_type) {
    case EVENT_TYPES.MESSAGE_SENT:
      activity.linkedinMsgSent = 1;
      activityNote = `[LinkedIn] Message sent: "${(data.message_text ?? "").slice(0, 500)}"`;
      break;

    case EVENT_TYPES.CONNECTION_REQUEST_SENT:
      activity.linkedinConnectionsSent = 1;
      activityNote = `[LinkedIn] Connection request sent to ${contactName}`;
      break;

    case EVENT_TYPES.CONNECTION_ACCEPTED:
      activity.linkedinReplies = 1;       // acceptance = positive reply signal
      activityNote = `[LinkedIn] Connection accepted by ${contactName}`;
      break;

    case EVENT_TYPES.MESSAGE_RECEIVED:
      activity.linkedinReplies = 1;
      activityNote = `[LinkedIn] Reply received: "${(data.message_text ?? "").slice(0, 500)}"`;
      break;

    case EVENT_TYPES.MEETING_BOOKED:
      activity.linkedinMeetingsBooked = 1;
      activityNote = `[LinkedIn] Meeting booked with ${contactName}`;
      break;

    default:
      log.warn("Unhandled Unipile event_type — skipping forward", { event_type });
      return null;   // caller responds 200 without forwarding
  }

  return {
    // Contact fields
    contactEmail,
    contactName,
    contactLinkedIn,

    // BD rep identifier
    bdRepAccountId: account_id ?? null,

    // Activity counters
    ...activity,

    // Activity note (maps to GHL "Activity Note" action)
    activityNote,

    // Date field (YYYY-MM-DD)
    liLastActivityDate: timestamp
      ? new Date(timestamp * 1000).toISOString().split("T")[0]
      : new Date().toISOString().split("T")[0],

    // Pass through so GHL workflow can branch on event type if needed
    sourceEventType: event_type,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// GHL FORWARDER — single retry with exponential back-off on network/5xx errors
// ─────────────────────────────────────────────────────────────────────────────
/**
 * @param {object} payload
 * @param {number} [attempt=1]
 * @returns {Promise<{statusCode: number, body: string}>}
 */
async function forwardToGHL(payload, attempt = 1) {
  const MAX_ATTEMPTS = 3;
  const url = new URL(CONFIG.GHL_WEBHOOK_URL);
  const bodyBuffer = Buffer.from(JSON.stringify(payload), "utf8");

  const options = {
    hostname: url.hostname,
    port:     url.port || 443,
    path:     url.pathname + url.search,
    method:   "POST",
    headers: {
      "Content-Type":   CONTENT_TYPE_JSON,
      "Content-Length": bodyBuffer.length,
      "User-Agent":     "Unipile-GHL-Middleware/1.0",
    },
    timeout: 10_000,
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end",  () => resolve({
        statusCode: res.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });

    req.on("timeout", () => req.destroy(new Error("GHL request timed out")));

    req.on("error", async (err) => {
      if (attempt < MAX_ATTEMPTS) {
        const delay = 500 * 2 ** (attempt - 1);   // 500 ms → 1 s → 2 s
        log.warn(`GHL forward attempt ${attempt} failed, retrying in ${delay}ms`, {
          error: err.message,
        });
        await new Promise((r) => setTimeout(r, delay));
        forwardToGHL(payload, attempt + 1).then(resolve).catch(reject);
      } else {
        reject(err);
      }
    });

    req.write(bodyBuffer);
    req.end();
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP HELPER
// ─────────────────────────────────────────────────────────────────────────────
function sendJson(res, statusCode, body) {
  const payload = JSON.stringify(body);
  res.writeHead(statusCode, {
    "Content-Type":            CONTENT_TYPE_JSON,
    "Content-Length":          Buffer.byteLength(payload),
    "X-Content-Type-Options":  "nosniff",
    "Cache-Control":           "no-store",
  });
  res.end(payload);
}

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST HANDLER
// ─────────────────────────────────────────────────────────────────────────────
async function handleRequest(req, res) {
  // ── Health check (used by DigitalOcean health probes, uptime monitors) ──
  if (req.method === "GET" && req.url === "/health") {
    return sendJson(res, 200, { status: "ok", ts: now() });
  }

  // ── Route: only POST /webhook ───────────────────────────────────────────
  if (req.method !== "POST" || req.url !== "/webhook") {
    return sendJson(res, 404, { error: "Not found" });
  }

  // ── Read body ───────────────────────────────────────────────────────────
  let rawBody;
  try {
    rawBody = await readBody(req);
  } catch (err) {
    return sendJson(res, err instanceof HttpError ? err.statusCode : 400, { error: err.message });
  }

  // ── Verify signature ────────────────────────────────────────────────────
  if (CONFIG.UNIPILE_WEBHOOK_SECRET) {
    const sig = (req.headers[UNIPILE_SIGNATURE_HEADER] ?? "").toString();
    if (!verifySignature(rawBody, sig, CONFIG.UNIPILE_WEBHOOK_SECRET)) {
      log.warn("Webhook signature verification failed", { ip: req.socket?.remoteAddress });
      return sendJson(res, 401, { error: "Invalid signature" });
    }
  } else {
    log.warn("UNIPILE_WEBHOOK_SECRET not set — skipping signature check (NOT safe for production)");
  }

  // ── Parse JSON ──────────────────────────────────────────────────────────
  let event;
  try {
    event = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return sendJson(res, 400, { error: "Invalid JSON body" });
  }

  log.info("Received Unipile webhook", { event_type: event.event_type });

  // ── Transform ───────────────────────────────────────────────────────────
  let ghlPayload;
  try {
    ghlPayload = transformEvent(event);
  } catch (err) {
    log.error("Payload transform error", { error: err.message });
    return sendJson(res, err instanceof HttpError ? err.statusCode : 500, { error: err.message });
  }

  if (ghlPayload === null) {
    return sendJson(res, 200, { status: "ignored", reason: "event_type not mapped to GHL action" });
  }

  // ── Validate GHL URL ────────────────────────────────────────────────────
  if (!CONFIG.GHL_WEBHOOK_URL) {
    log.error("GHL_WEBHOOK_URL env var is not set");
    return sendJson(res, 500, { error: "Middleware misconfiguration: GHL_WEBHOOK_URL missing" });
  }

  // ── Forward to GHL ──────────────────────────────────────────────────────
  try {
    const { statusCode, body } = await forwardToGHL(ghlPayload);

    if (statusCode >= 200 && statusCode < 300) {
      log.info("Event forwarded to GHL successfully", { ghlStatus: statusCode });
      return sendJson(res, 200, { status: "forwarded", ghlStatus: statusCode });
    }

    // GHL returned a non-2xx — log but acknowledge Unipile (avoid storm of retries)
    log.error("GHL returned non-2xx response", { ghlStatus: statusCode, body: body.slice(0, 512) });
    return sendJson(res, 200, { status: "ghl_error", ghlStatus: statusCode });

  } catch (err) {
    // Network failure after all retries — return 500 so Unipile retries delivery
    log.error("GHL forward failed after all retries", { error: err.message });
    return sendJson(res, 500, { error: "Failed to reach GHL webhook endpoint" });
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SERVER BOOTSTRAP
// ─────────────────────────────────────────────────────────────────────────────
function validateConfig() {
  if (!CONFIG.UNIPILE_WEBHOOK_SECRET)
    log.warn("UNIPILE_WEBHOOK_SECRET not set — UNSAFE for production");
  if (!CONFIG.GHL_WEBHOOK_URL)
    log.warn("GHL_WEBHOOK_URL not set — forward calls will fail");
}

const server = http.createServer(async (req, res) => {
  try {
    await handleRequest(req, res);
  } catch (err) {
    log.error("Unhandled exception in request handler", { error: err.message, stack: err.stack });
    if (!res.headersSent) sendJson(res, 500, { error: "Internal server error" });
  }
});

server.listen(CONFIG.PORT, () => {
  validateConfig();
  log.info("Unipile-GHL middleware started", { port: CONFIG.PORT });
});

// Graceful shutdown — PM2 / systemd / DigitalOcean App Platform all send SIGTERM
function shutdown() {
  log.info("Shutdown signal received — closing server gracefully");
  server.close(() => {
    log.info("Server closed");
    process.exit(0);
  });
  // Force exit after 10 s if hanging
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT",  shutdown);
