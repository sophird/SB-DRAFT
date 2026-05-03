require("dotenv").config();

const http = require("http");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { createClient } = require("@supabase/supabase-js");

let intentionalShutdown = false;

process.on("uncaughtException", (err) => {
  console.error("[backend] uncaughtException:", err);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("[backend] unhandledRejection:", reason);
  process.exit(1);
});

process.on("beforeExit", () => {
  if (intentionalShutdown) return;
  console.warn(
    "[backend] beforeExit — event loop is draining. If the server should still be running, something may have called process.exit() or left no active handles."
  );
});

process.on("exit", (code) => {
  if (!intentionalShutdown) {
    console.warn("[backend] process exit with code", code);
  }
});

const app = express();
const port = Number(process.env.PORT) || 4000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(
  cors({
    origin: (() => {
      const rawOrigins = process.env.CLIENT_ORIGIN;
      if (!rawOrigins) return true;
      const allowedOrigins = rawOrigins.split(",").map((origin) => origin.trim()).filter(Boolean);
      return allowedOrigins.length ? allowedOrigins : true;
    })()
  })
);
app.use(express.json({ limit: "48kb" }));

const authResidentRegisterLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many registration attempts. Please try again later." }
});

const authResidentLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many login attempts. Please try again later." }
});

const adminStaffCreateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many staff creation attempts. Please try again later." }
});

const faqSearchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many FAQ searches. Please try again later." }
});

const faqChatLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many chat messages. Please try again later." }
});

const adminAnalyticsDecisionInsightLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 24,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Too many decision-insight requests. Please try again later." }
});

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY
);
const supabaseAuth = createClient(
  process.env.SUPABASE_URL || "",
  process.env.SUPABASE_ANON_KEY || ""
);

const requestEventClients = new Set();
const appointmentEventClients = new Set();
const announcementEventClients = new Set();

const MAX_EMAIL_LEN = 254;
const MAX_FULL_NAME_LEN = 120;
const MAX_PASSWORD_LEN = 128;

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .slice(0, MAX_EMAIL_LEN);
}

function isValidEmailFormat(email) {
  if (!email || email.length > MAX_EMAIL_LEN) return false;
  const basic =
    /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i;
  return basic.test(String(email).trim());
}

function sanitizeFullNameForStorage(raw) {
  let s = String(raw || "")
    .trim()
    .replace(/[\x00-\x1f\x7f]/g, "");
  if (s.length > MAX_FULL_NAME_LEN) s = s.slice(0, MAX_FULL_NAME_LEN);
  s = s.replace(/[<>]/g, "");
  return s.trim();
}

const STAFF_PERMISSION_KEYS = ["dashboard", "appointmentScheduling", "requestProcessing", "documentGenerator"];

function defaultStaffPermissionsAllTrue() {
  return {
    dashboard: true,
    appointmentScheduling: true,
    requestProcessing: true,
    documentGenerator: true
  };
}

function normalizeStaffPermissionsFromDb(raw) {
  const base = defaultStaffPermissionsAllTrue();
  if (!raw || typeof raw !== "object") return base;
  for (const k of STAFF_PERMISSION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(raw, k)) {
      base[k] = Boolean(raw[k]);
    }
  }
  return base;
}

function normalizeStaffPermissionsFromBody(body) {
  const src = body && typeof body === "object" ? body : {};
  const out = {
    dashboard: false,
    appointmentScheduling: false,
    requestProcessing: false,
    documentGenerator: false
  };
  for (const k of STAFF_PERMISSION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(src, k)) {
      out[k] = Boolean(src[k]);
    }
  }
  return out;
}

function getBearerToken(req) {
  const authHeader = req.headers.authorization || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  return authHeader.slice("Bearer ".length).trim();
}

async function resolveProfileFromToken(req) {
  const token = getBearerToken(req);
  if (!token) {
    return { error: { status: 401, message: "Missing bearer token." } };
  }

  const { data: authUserData, error: authUserError } = await supabaseAuth.auth.getUser(token);
  if (authUserError || !authUserData?.user?.email) {
    return { error: { status: 401, message: "Invalid or expired session token." } };
  }

  const userEmail = authUserData.user.email;
  const { data: profile, error: profileError } = await supabaseAdmin
    .from("profiles")
    .select("email, full_name, role")
    .eq("email", userEmail)
    .maybeSingle();

  if (profileError) {
    return { error: { status: 500, message: "Unable to load user profile." } };
  }

  if (!profile) {
    return { error: { status: 403, message: "Profile record not found." } };
  }

  return { profile };
}

const STAFF_PORTAL_ROLES = new Set(["admin", "staff", "system-admin"]);

async function requireResidentPortalUser(req, res) {
  const { profile, error } = await resolveProfileFromToken(req);
  if (error) {
    res.status(error.status).json({ ok: false, message: error.message });
    return null;
  }
  if (profile.role !== "resident") {
    res.status(403).json({ ok: false, message: "Resident portal access required." });
    return null;
  }
  const residentUserId = await ensureResidentUserRow(profile.email);
  if (!residentUserId) {
    res.status(500).json({ ok: false, message: "Unable to resolve resident account." });
    return null;
  }
  return { profile, residentUserId };
}

async function requireStaffOrAuthenticatedResident(req, res) {
  const { profile, error } = await resolveProfileFromToken(req);
  if (error) {
    res.status(error.status).json({ ok: false, message: error.message });
    return null;
  }
  if (STAFF_PORTAL_ROLES.has(profile.role)) {
    return { portal: "staff", profile };
  }
  if (profile.role === "resident") {
    const residentUserId = await ensureResidentUserRow(profile.email);
    if (!residentUserId) {
      res.status(500).json({ ok: false, message: "Unable to resolve resident account." });
      return null;
    }
    return { portal: "resident", profile, residentUserId };
  }
  res.status(403).json({ ok: false, message: "Access denied." });
  return null;
}

async function validateSseAccess(req) {
  const token = getBearerToken(req) || String(req.query?.access_token || "").trim();
  if (!token) return { ok: false, status: 401, message: "Authentication required." };
  const { data: authUserData, error: authUserError } = await supabaseAuth.auth.getUser(token);
  if (authUserError || !authUserData?.user?.email) {
    return { ok: false, status: 401, message: "Invalid or expired session token." };
  }
  const userEmail = authUserData.user.email;
  const { data: profile, error: profileError } = await supabaseAdmin
    .from("profiles")
    .select("email, role")
    .eq("email", userEmail)
    .maybeSingle();
  if (profileError || !profile) {
    return { ok: false, status: 403, message: "Profile record not found." };
  }
  if (profile.role !== "resident" && !STAFF_PORTAL_ROLES.has(profile.role)) {
    return { ok: false, status: 403, message: "Access denied." };
  }
  return { ok: true, profile };
}

const MAX_REQUEST_TITLE_LEN = 200;
const MAX_SERVICE_TYPE_LEN = 120;
const MAX_TIME_SLOT_LEN = 80;
const MAX_APPOINTMENT_PURPOSE_LEN = 200;
const MAX_STATUS_NOTE_LEN = 2000;
const MAX_ANNOUNCEMENT_TITLE_LEN = 200;
const MAX_ANNOUNCEMENT_BODY_LEN = 8000;
const MAX_ANNOUNCEMENT_CATEGORY_LEN = 80;
const MAX_FAQ_SEARCH_QUERY_LEN = 800;
const FAQ_SEARCH_MIN_SCORE = 4;
const FAQ_SEARCH_TOP_LIMIT_DEFAULT = 3;
const FAQ_SEARCH_TOP_LIMIT_MAX = 8;
const FAQ_CHAT_CONTEXT_MAX = 5;
const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_CHAT_DEFAULT_MODEL = "llama-3.3-70b-versatile";
const MAX_GROQ_REPLY_CHARS = 4000;
const FAQ_SEARCH_TOKEN_STOPWORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "as",
  "at",
  "be",
  "but",
  "by",
  "can",
  "did",
  "do",
  "does",
  "for",
  "from",
  "had",
  "has",
  "have",
  "how",
  "i",
  "if",
  "in",
  "into",
  "is",
  "it",
  "its",
  "me",
  "my",
  "not",
  "of",
  "on",
  "or",
  "our",
  "see",
  "so",
  "than",
  "that",
  "the",
  "their",
  "them",
  "then",
  "there",
  "these",
  "they",
  "this",
  "those",
  "to",
  "too",
  "use",
  "was",
  "we",
  "were",
  "what",
  "when",
  "where",
  "which",
  "who",
  "whose",
  "why",
  "will",
  "with",
  "you",
  "your",
  // Common Filipino fillers (queries may mix languages)
  "po",
  "opo",
  "ba",
  "lang",
  "lng",
  "ko",
  "mo",
  "na"
]);

// Stored FAQ keywords this short or this generic are ignored for substring matching (avoid ranking noise).
const FAQ_SEARCH_IGNORED_KEYWORD_SUBSTRINGS = new Set([
  "how",
  "why",
  "when",
  "who",
  "what",
  "which",
  "where",
  "there",
  "here"
]);

function sanitizePlainTextField(raw, maxLen) {
  let s = String(raw || "")
    .trim()
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
  if (s.length > maxLen) s = s.slice(0, maxLen);
  return s.replace(/[<>]/g, "").trim();
}

function parseLocalDateString(value) {
  const s = String(value || "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(`${s}T12:00:00Z`);
  if (Number.isNaN(d.getTime())) return null;
  return s;
}

async function getAppointmentSlotCapacityForDate(slotId, dateISO) {
  const parsedSlotId = Number(slotId);
  if (!Number.isInteger(parsedSlotId) || parsedSlotId <= 0) return null;
  const safeDate = parseLocalDateString(dateISO);
  if (!safeDate) return null;

  const [slotResult, overrideResult] = await Promise.all([
    supabaseAdmin.from("appointment_slots").select("id, default_capacity, is_active").eq("id", parsedSlotId).maybeSingle(),
    supabaseAdmin
      .from("appointment_slot_overrides")
      .select("capacity_limit")
      .eq("slot_id", parsedSlotId)
      .eq("override_date", safeDate)
      .maybeSingle()
  ]);

  if (slotResult.error || !slotResult.data) return null;
  if (slotResult.data.is_active === false) return null;

  const overrideCap = Number(overrideResult?.data?.capacity_limit);
  if (Number.isInteger(overrideCap) && overrideCap > 0) return overrideCap;

  const defaultCap = Number(slotResult.data.default_capacity);
  if (!Number.isInteger(defaultCap) || defaultCap <= 0) return null;
  return defaultCap;
}

async function countBookedAppointmentsForSlot(slotId, dateISO) {
  const parsedSlotId = Number(slotId);
  if (!Number.isInteger(parsedSlotId) || parsedSlotId <= 0) return null;
  const safeDate = parseLocalDateString(dateISO);
  if (!safeDate) return null;

  const { count, error } = await supabaseAdmin
    .from("appointments")
    .select("id", { count: "exact", head: true })
    .eq("slot_id", parsedSlotId)
    .eq("appointment_date", safeDate)
    .not("status", "in", "(Rejected,Cancelled)");

  if (error) return null;
  return Number.isInteger(count) ? count : 0;
}

async function requireStaffPortalUser(req, res) {
  const { profile, error } = await resolveProfileFromToken(req);
  if (error) {
    res.status(error.status).json({ ok: false, message: error.message });
    return null;
  }
  if (!STAFF_PORTAL_ROLES.has(profile.role)) {
    res.status(403).json({ ok: false, message: "Admin portal access required." });
    return null;
  }
  return { profile };
}

function normalizeAnnouncementRow(row) {
  return {
    id: row.id,
    category: row.category,
    title: row.title,
    body: row.body,
    isActive: row.is_active,
    createdAt: row.created_at,
    postedByRole: row.posted_by_role ?? null
  };
}

function normalizeServiceCatalogRow(row) {
  return {
    id: row.id,
    name: row.service_name,
    requiredDocuments: row.required_documents,
    processingTime: row.processing_time,
    status: row.status,
    archivedAt: row.archived_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function normalizeFaqSearchText(raw) {
  return String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "");
}

function tokenizeForFaqSearch(normalizedLower) {
  return normalizedLower
    .split(/[^\p{L}\p{N}]+/u)
    .map((t) => t.trim())
    .filter((t) => t.length >= 2);
}

function significantFaqTokensFromField(text) {
  const bag = new Set();
  for (const t of tokenizeForFaqSearch(normalizeFaqSearchText(text))) {
    if (t.length < 2 || FAQ_SEARCH_TOKEN_STOPWORDS.has(t)) continue;
    bag.add(t);
  }
  return bag;
}

function scoreFaqEntry(normalizedMessage, tokens, row) {
  let score = 0;
  const reasons = [];
  const keywords = Array.isArray(row.keywords) ? row.keywords : [];

  for (const kw of keywords) {
    const k = normalizeFaqSearchText(kw);
    if (k.length < 3 || FAQ_SEARCH_IGNORED_KEYWORD_SUBSTRINGS.has(k)) continue;
    if (normalizedMessage.includes(k)) {
      score += 6;
      reasons.push(`keyword:${k.slice(0, 64)}`);
    }
  }

  const questionTok = significantFaqTokensFromField(row.question);
  const answerTok = significantFaqTokensFromField(row.answer);

  for (const t of tokens) {
    if (t.length < 2 || FAQ_SEARCH_TOKEN_STOPWORDS.has(t)) continue;
    if (questionTok.has(t)) {
      score += 3;
      reasons.push(`question:${t}`);
    } else if (answerTok.has(t)) {
      score += 1;
      reasons.push(`answer:${t}`);
    }
  }

  return { score, reasons: [...new Set(reasons)].slice(0, 12) };
}

function normalizeFaqMatch(row, score, reasons) {
  return {
    id: row.id,
    category: row.category,
    question: row.question,
    answer: row.answer,
    score,
    matchReasons: reasons,
    sortOrder: row.sort_order
  };
}

async function retrieveFaqMatchesInternal(query, limit) {
  const { data, error } = await supabaseAdmin
    .from("faq_entries")
    .select("id,category,question,answer,keywords,sort_order")
    .eq("is_active", true)
    .order("sort_order", { ascending: true });

  if (error) {
    return {
      ok: false,
      message: "Unable to load FAQs.",
      detail: error.message
    };
  }

  const normalizedMessage = normalizeFaqSearchText(query);
  const tokens = tokenizeForFaqSearch(normalizedMessage);

  const scored = (data || [])
    .map((row) => {
      const { score, reasons } = scoreFaqEntry(normalizedMessage, tokens, row);
      return { row, score, reasons };
    })
    .filter((x) => x.score >= FAQ_SEARCH_MIN_SCORE)
    .sort((a, b) => {
      if (b.score !== a.score) return b.score - a.score;
      return (a.row.sort_order ?? 0) - (b.row.sort_order ?? 0);
    })
    .slice(0, limit);

  const bestScore = scored.length ? scored[0].score : 0;
  let confidence = "none";
  if (bestScore >= 12) confidence = "high";
  else if (bestScore >= FAQ_SEARCH_MIN_SCORE) confidence = "low";

  return {
    ok: true,
    query,
    matches: scored.map(({ row, score, reasons }) => normalizeFaqMatch(row, score, reasons)),
    bestScore,
    confidence
  };
}

function buildFaqContextBlock(matches) {
  return matches
    .map((m, i) => {
      return `[${i + 1}] (${m.category})\nQ: ${m.question}\nA: ${m.answer}`;
    })
    .join("\n\n");
}

function sanitizeChatReply(raw) {
  let s = String(raw || "")
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, "")
    .trim();
  if (s.length > MAX_GROQ_REPLY_CHARS) s = s.slice(0, MAX_GROQ_REPLY_CHARS).trim();
  return s.replace(/[<>]/g, "");
}

async function rewriteFaqWithGroq(userQuestion, matches) {
  const apiKey = String(process.env.GROQ_API_KEY || "").trim();
  if (!apiKey) {
    return { ok: false, reason: "no_api_key" };
  }

  const model = String(process.env.GROQ_MODEL || "").trim() || GROQ_CHAT_DEFAULT_MODEL;
  const excerpts = buildFaqContextBlock(matches);

  const systemPrompt = [
    "You are a Philippine barangay resident assistant answering questions using ONLY the FAQ excerpts provided by the user message.",
    "Understand the user's question whether it is in English, Tagalog, Taglish, or mixed—then reply in CLEAR, EASY-TO-READ English suited for non-technical residents.",
    "Rewrite faithfully: simplify wording and sentence length, prefer short bullets when helpful, but do NOT remove required steps, conditions, statuses, dashboard names, or fees that appear in the excerpts.",
    "Keep these exact phrases when referring to portals (capitalization as in excerpts): \"Service Requests\", \"Recent Service Requests\", and \"Request History\"—these may become clickable links in the app.",
    "Do not invent requirements, deadlines, contacts, URLs, offices, amounts, fees, portal names, or processes that are not in the excerpts.",
    "If excerpts do not cover part of the question, say clearly in simple English what is unknown and advise visiting/contacting the barangay.",
    "Do not prefix answers like \"FAQ 1\". No markdown/HTML."
  ].join("\n");

  const userPayload = [
    "Do this:",
    "1) Read the RESIDENT QUESTION below (English/Tagalog/Taglish acceptable). Understand intent.",
    "2) Decide which excerpt(s) apply.",
    "3) Answer in SIMPLE English using ONLY excerpt facts.",
    "",
    `RESIDENT QUESTION:\n${userQuestion}`,
    "",
    `OFFICIAL FAQ EXCERPTS:\n${excerpts}`
  ].join("\n");

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), 45000);

  try {
    const res = await fetch(GROQ_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: userPayload }
        ],
        temperature: 0.2,
        max_tokens: 700
      }),
      signal: ac.signal
    });

    const rawText = await res.text();
    let json;
    try {
      json = JSON.parse(rawText);
    } catch {
      return { ok: false, reason: "bad_response", status: res.status, detail: rawText.slice(0, 400) };
    }

    if (!res.ok) {
      const msg = json?.error?.message || rawText.slice(0, 400);
      return { ok: false, reason: "groq_http", status: res.status, detail: msg };
    }

    const text = sanitizeChatReply(json?.choices?.[0]?.message?.content);
    if (!text) {
      return { ok: false, reason: "empty_content" };
    }

    return { ok: true, text, model };
  } catch (err) {
    if (err?.name === "AbortError") {
      return { ok: false, reason: "timeout" };
    }
    return { ok: false, reason: "network", detail: String(err?.message || err).slice(0, 400) };
  } finally {
    clearTimeout(timer);
  }
}

// Return basic API status and whether Supabase env vars are present.
app.get("/health", async (_req, res) => {
  // Lightweight check that API server is up and env is loaded.
  const hasSupabaseConfig = Boolean(
    process.env.SUPABASE_URL &&
      (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY)
  );
  const groqConfigured = Boolean(String(process.env.GROQ_API_KEY || "").trim());

  res.json({
    ok: true,
    service: "backend",
    supabaseConfigured: hasSupabaseConfig,
    groqConfigured
  });
});

// Return a lightweight readiness check for Supabase client setup.
app.get("/supabase/health", async (_req, res) => {
  const configured = Boolean(
    process.env.SUPABASE_URL &&
      (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY)
  );
  const clientReady =
    typeof supabaseAdmin.from === "function" && typeof supabaseAuth.auth?.signInWithPassword === "function";
  return res.json({ ok: configured && clientReady });
});

app.get("/auth/config", async (_req, res) => {
  const supabaseUrl = String(process.env.SUPABASE_URL || "").trim();
  const supabaseAnonKey = String(process.env.SUPABASE_ANON_KEY || "").trim();
  if (!supabaseUrl || !supabaseAnonKey) {
    return res.status(500).json({
      ok: false,
      message: "Supabase public config is not available."
    });
  }

  return res.json({
    ok: true,
    supabaseUrl,
    supabaseAnonKey
  });
});

// Authenticate an admin account and return auth session details.
app.post("/auth/admin/login", async (req, res) => {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      ok: false,
      message: "Email and password are required."
    });
  }

  const { data: authData, error: authError } = await supabaseAuth.auth.signInWithPassword({
    email,
    password
  });

  if (authError || !authData?.user) {
    return res.status(401).json({
      ok: false,
      message: "Invalid email or password."
    });
  }

  const { data: profile, error: profileError } = await supabaseAdmin
    .from("profiles")
    .select("email, full_name, role, staff_permissions")
    .eq("email", email)
    .maybeSingle();

  if (profileError) {
    return res.status(500).json({
      ok: false,
      message: "Unable to verify admin role."
    });
  }

  const allowedAdminRoles = new Set(["admin", "staff", "system-admin"]);
  if (!profile || !allowedAdminRoles.has(profile.role)) {
    await supabaseAuth.auth.signOut();
    return res.status(403).json({
      ok: false,
      message: "Access denied. Admin portal account required."
    });
  }

  const userPayload = {
    email: profile.email,
    fullName: profile.full_name,
    role: profile.role
  };
  if (profile.role === "staff") {
    userPayload.staffPermissions = normalizeStaffPermissionsFromDb(profile.staff_permissions);
  }

  return res.json({
    ok: true,
    message: "Login successful.",
    user: userPayload,
    session: {
      accessToken: authData.session?.access_token || null,
      refreshToken: authData.session?.refresh_token || null,
      expiresAt: authData.session?.expires_at || null
    }
  });
});

app.get("/auth/admin/authorize/:requiredRole", async (req, res) => {
  const role = String(req.params.requiredRole || "").trim();
  const roleMap = {
    admin: ["admin"],
    staff: ["staff"],
    "system-admin": ["system-admin"]
  };

  const allowedRoles = roleMap[role];
  if (!allowedRoles) {
    return res.status(400).json({
      ok: false,
      message: "Unsupported role authorization target."
    });
  }

  const { profile, error } = await resolveProfileFromToken(req);
  if (error) {
    return res.status(error.status).json({
      ok: false,
      message: error.message
    });
  }

  if (!allowedRoles.includes(profile.role)) {
    return res.status(403).json({
      ok: false,
      message: "Access denied for this role."
    });
  }

  return res.json({
    ok: true,
    user: {
      email: profile.email,
      fullName: profile.full_name,
      role: profile.role
    }
  });
});

const STAFF_LINEAR_SERVICE_REQUEST_STATUSES = new Set(["Processing", "Ready for Pickup", "Completed", "Rejected"]);
const STAFF_LINEAR_APPOINTMENT_STATUSES = new Set(["Processing", "Ready for Pickup", "Completed", "Rejected"]);

function parseStatusTimeline(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.filter((x) => x && typeof x === "object");
  if (typeof raw === "string") {
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((x) => x && typeof x === "object") : [];
    } catch {
      return [];
    }
  }
  return [];
}

function timelineForApiResponse(kind, row) {
  const stored = parseStatusTimeline(row.status_timeline);
  if (stored.length) return stored;
  const at = row.created_at ? String(row.created_at) : null;
  const fallbackStatus =
    kind === "appointment"
      ? String(row.status || "Pending Review")
      : String(row.status || "Pending");
  if (!at) {
    return [{ status: fallbackStatus, at: new Date().toISOString(), note: null }];
  }
  return [{ status: fallbackStatus, at, note: null }];
}

function buildNextTimelineFromRow(row, incomingStatus, noteText) {
  const prevTimeline = parseStatusTimeline(row.status_timeline);
  const safeNote =
    typeof noteText === "string" && noteText.trim()
      ? sanitizePlainTextField(noteText, MAX_STATUS_NOTE_LEN)
      : null;
  const entry = {
    status: String(incomingStatus),
    at: new Date().toISOString(),
    note: safeNote || null
  };
  if (!prevTimeline.length) {
    const anchorAt = row.created_at ? String(row.created_at) : entry.at;
    return [{ status: String(row.status ?? ""), at: anchorAt, note: null }, entry];
  }
  return [...prevTimeline, entry];
}

function requestWorkflowStage(status) {
  const s = String(status || "").trim().toLowerCase();
  if (s === "pending") return 0;
  if (s === "processing" || s === "in progress") return 1;
  if (s === "ready for pickup") return 2;
  if (s === "completed") return 3;
  if (s === "rejected") return "reject";
  return "other";
}

function appointmentWorkflowStage(status) {
  const s = String(status || "").trim().toLowerCase();
  if (s === "pending review") return 0;
  if (s === "processing" || s === "confirmed") return 1;
  if (s === "ready for pickup") return 2;
  if (s === "completed") return 3;
  if (s === "rejected") return "reject";
  if (s === "cancelled") return "cancelled";
  return "other";
}

function validateStaffServiceRequestTransition(currentStatus, incomingStatus) {
  const incoming = String(incomingStatus || "").trim();
  if (!STAFF_LINEAR_SERVICE_REQUEST_STATUSES.has(incoming)) {
    return { ok: true };
  }
  const stage = requestWorkflowStage(currentStatus);
  if (stage === "reject" || stage === "other") {
    return {
      ok: false,
      message: "Cannot change status once the request is closed or not in workflow."
    };
  }
  if (incoming === "Rejected") {
    if (stage === 0 || stage === 1) return { ok: true };
    return {
      ok: false,
      message: "Reject is only allowed while the request is Pending or Processing."
    };
  }
  if (incoming === "Processing") {
    if (stage === 0) return { ok: true };
    return { ok: false, message: "Processing is only available while the request is Pending." };
  }
  if (incoming === "Ready for Pickup") {
    if (stage === 1) return { ok: true };
    return {
      ok: false,
      message: "Ready for Pickup is only available while the request is Processing."
    };
  }
  if (incoming === "Completed") {
    if (stage === 2) return { ok: true };
    return { ok: false, message: "Completed is only available after Ready for Pickup." };
  }
  return { ok: false, message: "Invalid status transition." };
}

function validateStaffAppointmentTransition(currentStatus, incomingStatus) {
  const incoming = String(incomingStatus || "").trim();
  if (!STAFF_LINEAR_APPOINTMENT_STATUSES.has(incoming)) {
    return { ok: true };
  }
  const stage = appointmentWorkflowStage(currentStatus);
  if (stage === "reject" || stage === "cancelled" || stage === "other") {
    return {
      ok: false,
      message: "Cannot change status once the appointment is closed or not in workflow."
    };
  }
  if (incoming === "Rejected") {
    if (stage === 0 || stage === 1) return { ok: true };
    return {
      ok: false,
      message: "Reject is only allowed while the appointment is Pending Review or Processing."
    };
  }
  if (incoming === "Processing") {
    if (stage === 0) return { ok: true };
    return { ok: false, message: "Processing is only available while the appointment is Pending Review." };
  }
  if (incoming === "Ready for Pickup") {
    if (stage === 1) return { ok: true };
    return {
      ok: false,
      message: "Ready for Pickup is only available while the appointment is Processing."
    };
  }
  if (incoming === "Completed") {
    if (stage === 2) return { ok: true };
    return { ok: false, message: "Completed is only available after Ready for Pickup." };
  }
  return { ok: false, message: "Invalid status transition." };
}

function normalizeRequestRow(row) {
  return {
    id: row.id,
    referenceNo: row.reference_no,
    residentUserId: row.resident_user_id ?? null,
    title: row.title,
    serviceType: row.service_type,
    description: row.description ?? null,
    purpose: row.purpose ?? null,
    preferredDate: row.preferred_date,
    preferredTimeSlot: row.preferred_time_slot,
    status: row.status,
    createdAt: row.created_at || row.submitted_at || null,
    statusTimeline: timelineForApiResponse("request", row)
  };
}

function normalizeAppointmentRow(row) {
  return {
    id: row.id,
    referenceNo: row.reference_no,
    residentUserId: row.resident_user_id ?? null,
    purpose: row.purpose,
    notes: row.notes ?? null,
    appointmentDate: row.appointment_date,
    slotId: row.slot_id || null,
    timeLabel: row.appointment_slots?.label || null,
    status: row.status,
    createdAt: row.created_at || null,
    statusTimeline: timelineForApiResponse("appointment", row)
  };
}

async function getResidentDisplayNameForStaff(residentUserId) {
  const id = parseResidentUserId(residentUserId);
  if (!id) return "Unknown resident";
  const { data: userRow, error: userErr } = await supabaseAdmin.from("users").select("email").eq("id", id).maybeSingle();
  if (userErr || !userRow?.email) {
    return `Resident #${id}`;
  }
  const email = String(userRow.email).trim();
  const { data: prof } = await supabaseAdmin.from("profiles").select("full_name").eq("email", email).maybeSingle();
  const fullName = String(prof?.full_name || "").trim();
  if (fullName) return fullName;
  return email;
}

async function normalizeRequestRowWithResident(row) {
  const base = normalizeRequestRow(row);
  const residentName = await getResidentDisplayNameForStaff(row?.resident_user_id);
  return { ...base, residentName };
}

async function normalizeAppointmentRowWithResident(row) {
  const base = normalizeAppointmentRow(row);
  const residentName = await getResidentDisplayNameForStaff(row?.resident_user_id);
  return { ...base, residentName };
}

function broadcastRequestEvent(payload) {
  const packet = `event: request-updated\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of requestEventClients) {
    try {
      client.write(packet);
    } catch (_error) {
      requestEventClients.delete(client);
    }
  }
}

function broadcastAppointmentEvent(payload) {
  const packet = `event: appointment-updated\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of appointmentEventClients) {
    try {
      client.write(packet);
    } catch (_error) {
      appointmentEventClients.delete(client);
    }
  }
}

function broadcastAnnouncementEvent(payload) {
  const packet = `event: announcements-changed\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of announcementEventClients) {
    try {
      client.write(packet);
    } catch (_error) {
      announcementEventClients.delete(client);
    }
  }
}

async function ensureResidentUserRow(email) {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail) return null;

  const { data: existing, error: existingError } = await supabaseAdmin
    .from("users")
    .select("id")
    .eq("email", normalizedEmail)
    .maybeSingle();

  if (!existingError && existing?.id) return existing.id;

  const { data: inserted, error: insertError } = await supabaseAdmin
    .from("users")
    .insert({
      email: normalizedEmail,
      role: "resident",
      auth_provider: "local",
      is_active: true
    })
    .select("id")
    .maybeSingle();

  if (!insertError && inserted?.id) return inserted.id;

  const { data: fallbackByEmail } = await supabaseAdmin
    .from("users")
    .select("id")
    .eq("email", normalizedEmail)
    .maybeSingle();

  return fallbackByEmail?.id || null;
}

async function upsertResidentProfile({ email, fullName, residentSelfRegistered = false }) {
  const normalizedEmail = normalizeEmail(email);
  const safeFullName = sanitizeFullNameForStorage(fullName);
  if (!normalizedEmail || !safeFullName) {
    return { ok: false, message: "Email and full name are required." };
  }

  const upsertPayload = {
    email: normalizedEmail,
    full_name: safeFullName,
    role: "resident",
    resident_self_registered: Boolean(residentSelfRegistered)
  };

  const { error } = await supabaseAdmin.from("profiles").upsert(upsertPayload, { onConflict: "email" });
  if (error) {
    return { ok: false, message: "Unable to save resident profile.", detail: error.message };
  }

  return { ok: true };
}

function parseResidentUserId(rawValue) {
  if (rawValue === undefined || rawValue === null || rawValue === "") return null;
  const parsed = Number(rawValue);
  if (!Number.isInteger(parsed) || parsed <= 0) return null;
  return parsed;
}

app.post("/auth/resident/register", authResidentRegisterLimiter, async (req, res) => {
  const { fullName, email, password } = req.body || {};
  const normalizedEmail = normalizeEmail(email);
  const safeFullName = sanitizeFullNameForStorage(fullName);
  const safePassword = String(password || "");

  if (!safeFullName || !normalizedEmail || !safePassword) {
    return res.status(400).json({
      ok: false,
      message: "fullName, email, and password are required."
    });
  }

  if (!isValidEmailFormat(normalizedEmail)) {
    return res.status(400).json({
      ok: false,
      message: "Please enter a valid email address."
    });
  }

  if (safePassword.length < 8) {
    return res.status(400).json({
      ok: false,
      message: "Password must be at least 8 characters long."
    });
  }

  if (safePassword.length > MAX_PASSWORD_LEN) {
    return res.status(400).json({
      ok: false,
      message: `Password must be at most ${MAX_PASSWORD_LEN} characters.`
    });
  }

  // Password hashing and storage are handled by Supabase Auth (auth.users). Application tables
  // never store plaintext passwords. Database access uses parameterized Supabase APIs (SQL injection safe).

  const { data: signUpData, error: signUpError } = await supabaseAuth.auth.signUp({
    email: normalizedEmail,
    password: safePassword,
    options: {
      data: {
        full_name: safeFullName,
        role: "resident"
      }
    }
  });

  if (signUpError) {
    return res.status(400).json({
      ok: false,
      message: signUpError.message || "Unable to register resident account."
    });
  }

  const profileResult = await upsertResidentProfile({
    email: normalizedEmail,
    fullName: safeFullName,
    residentSelfRegistered: true
  });
  if (!profileResult.ok) {
    return res.status(500).json({
      ok: false,
      message: profileResult.message,
      detail: profileResult.detail
    });
  }

  const residentUserId = await ensureResidentUserRow(normalizedEmail);
  if (!residentUserId) {
    return res.status(500).json({
      ok: false,
      message: "Unable to link resident account to internal user record."
    });
  }

  return res.status(201).json({
    ok: true,
    message: "Resident account created.",
    stored: true,
    user: {
      email: normalizedEmail,
      fullName: safeFullName,
      role: "resident",
      residentUserId
    }
  });
});

app.post("/auth/resident/login", authResidentLoginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  const normalizedEmail = normalizeEmail(email);
  const safePassword = String(password || "");

  if (!normalizedEmail || !safePassword) {
    return res.status(400).json({
      ok: false,
      message: "Email and password are required."
    });
  }

  if (!isValidEmailFormat(normalizedEmail) || safePassword.length > MAX_PASSWORD_LEN) {
    return res.status(400).json({
      ok: false,
      message: "Invalid email or password."
    });
  }

  const { data: authData, error: authError } = await supabaseAuth.auth.signInWithPassword({
    email: normalizedEmail,
    password: safePassword
  });

  if (authError || !authData?.user) {
    return res.status(401).json({
      ok: false,
      message: "Invalid email or password."
    });
  }

  const { data: profile, error: profileError } = await supabaseAdmin
    .from("profiles")
    .select("email, full_name, role")
    .eq("email", normalizedEmail)
    .maybeSingle();

  if (profileError) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load resident profile."
    });
  }

  if (!profile || profile.role !== "resident") {
    await supabaseAuth.auth.signOut();
    return res.status(403).json({
      ok: false,
      message: "Access denied. Resident portal account required."
    });
  }

  const residentUserId = await ensureResidentUserRow(normalizedEmail);
  if (!residentUserId) {
    return res.status(500).json({
      ok: false,
      message: "Unable to link resident account to internal user record."
    });
  }

  return res.json({
    ok: true,
    message: "Login successful.",
    user: {
      email: profile.email,
      fullName: profile.full_name,
      role: profile.role,
      residentUserId
    },
    session: {
      accessToken: authData.session?.access_token || null,
      refreshToken: authData.session?.refresh_token || null,
      expiresAt: authData.session?.expires_at || null
    }
  });
});

app.get("/auth/resident/authorize", async (req, res) => {
  const { profile, error } = await resolveProfileFromToken(req);
  if (error) {
    return res.status(error.status).json({ ok: false, message: error.message });
  }
  if (profile.role !== "resident") {
    return res.status(403).json({ ok: false, message: "Resident portal access required." });
  }

  const residentUserId = await ensureResidentUserRow(profile.email);
  if (!residentUserId) {
    return res.status(500).json({
      ok: false,
      message: "Unable to resolve resident account."
    });
  }

  return res.json({
    ok: true,
    user: {
      email: profile.email,
      fullName: profile.full_name,
      role: profile.role,
      residentUserId
    }
  });
});

app.get("/resident/context", async (req, res) => {
  const auth = await requireResidentPortalUser(req, res);
  if (!auth) return;
  return res.json({
    ok: true,
    residentUserId: auth.residentUserId,
    fullName: auth.profile?.full_name || null,
    email: auth.profile?.email || null
  });
});

/** Services residents may request (matches admin catalog: Active and not archived). */
app.get("/resident/service-catalog", async (req, res) => {
  const auth = await requireResidentPortalUser(req, res);
  if (!auth) return;

  const { data, error } = await supabaseAdmin
    .from("service_catalog")
    .select("*")
    .is("archived_at", null)
    .eq("status", "Active")
    .order("service_name", { ascending: true });

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load service catalog.",
      detail: error.message
    });
  }

  return res.json({
    ok: true,
    services: (data || []).map(normalizeServiceCatalogRow)
  });
});

// Combined service requests + appointments for a resident, newest activity first.
app.get("/resident/history", async (req, res) => {
  const auth = await requireResidentPortalUser(req, res);
  if (!auth) return;
  const residentUserId = auth.residentUserId;

  const [requestsResult, appointmentsResult] = await Promise.all([
    supabaseAdmin.from("service_requests").select("*").eq("resident_user_id", residentUserId),
    supabaseAdmin
      .from("appointments")
      .select("*, appointment_slots(label)")
      .eq("resident_user_id", residentUserId)
  ]);

  if (requestsResult.error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load request history.",
      detail: requestsResult.error.message
    });
  }
  if (appointmentsResult.error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load appointment history.",
      detail: appointmentsResult.error.message
    });
  }

  const requests = (requestsResult.data || []).map(normalizeRequestRow);
  const appointments = (appointmentsResult.data || []).map(normalizeAppointmentRow);

  const items = [
    ...requests.map((request) => ({
      kind: "request",
      sortAt: request.createdAt || null,
      request
    })),
    ...appointments.map((appointment) => ({
      kind: "appointment",
      sortAt: appointment.createdAt || null,
      appointment
    }))
  ].sort((a, b) => {
    const left = new Date(a.sortAt || 0).getTime();
    const right = new Date(b.sortAt || 0).getTime();
    return right - left;
  });

  return res.json({
    ok: true,
    items
  });
});

app.get("/requests/events", async (req, res) => {
  const gate = await validateSseAccess(req);
  if (!gate.ok) {
    res.status(gate.status).setHeader("Content-Type", "text/plain").send(gate.message);
    return;
  }
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  res.write(`event: ready\ndata: {"ok":true}\n\n`);
  requestEventClients.add(res);

  req.on("close", () => {
    requestEventClients.delete(res);
  });
});

app.get("/appointments/events", async (req, res) => {
  const gate = await validateSseAccess(req);
  if (!gate.ok) {
    res.status(gate.status).setHeader("Content-Type", "text/plain").send(gate.message);
    return;
  }
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  res.write(`event: ready\ndata: {"ok":true}\n\n`);
  appointmentEventClients.add(res);

  req.on("close", () => {
    appointmentEventClients.delete(res);
  });
});

app.get("/announcements/events", async (req, res) => {
  const gate = await validateSseAccess(req);
  if (!gate.ok) {
    res.status(gate.status).setHeader("Content-Type", "text/plain").send(gate.message);
    return;
  }
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  res.write(`event: ready\ndata: {"ok":true}\n\n`);
  announcementEventClients.add(res);

  req.on("close", () => {
    announcementEventClients.delete(res);
  });
});

// --- Appointment slot availability (staff + resident) ---

app.get("/appointment-slots", async (req, res) => {
  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  const dateISO = parseLocalDateString(req.query?.date);
  if (!dateISO) {
    return res.status(400).json({ ok: false, message: "date (YYYY-MM-DD) is required." });
  }

  const { data: slots, error: slotsError } = await supabaseAdmin
    .from("appointment_slots")
    .select("id, slot_code, label, default_capacity, is_active, is_morning_pickup_only, phase_label")
    .eq("is_active", true)
    .order("id", { ascending: true });

  if (slotsError) {
    return res.status(500).json({ ok: false, message: "Unable to load appointment slots.", detail: slotsError.message });
  }

  const { data: overrides, error: overrideError } = await supabaseAdmin
    .from("appointment_slot_overrides")
    .select("slot_id, capacity_limit")
    .eq("override_date", dateISO);

  if (overrideError) {
    return res.status(500).json({ ok: false, message: "Unable to load appointment slot overrides.", detail: overrideError.message });
  }

  const overrideMap = new Map((overrides || []).map((o) => [Number(o.slot_id), Number(o.capacity_limit)]));

  const { data: bookedRows, error: bookedError } = await supabaseAdmin
    .from("appointments")
    .select("slot_id")
    .eq("appointment_date", dateISO)
    .not("status", "in", "(Rejected,Cancelled)");

  if (bookedError) {
    return res.status(500).json({ ok: false, message: "Unable to load appointment bookings.", detail: bookedError.message });
  }

  const bookedCountBySlot = new Map();
  for (const row of bookedRows || []) {
    const id = Number(row.slot_id);
    if (!Number.isInteger(id) || id <= 0) continue;
    bookedCountBySlot.set(id, (bookedCountBySlot.get(id) || 0) + 1);
  }

  const results = (slots || []).map((slot) => {
    const slotId = Number(slot.id);
    const overrideCap = overrideMap.get(slotId);
    const capacity =
      Number.isInteger(overrideCap) && overrideCap > 0 ? overrideCap : Number(slot.default_capacity || 0);
    const booked = bookedCountBySlot.get(slotId) || 0;
    const remaining = Math.max(0, capacity - booked);
    return {
      id: slotId,
      code: slot.slot_code,
      label: slot.label,
      phaseLabel: slot.phase_label || null,
      isMorningPickupOnly: Boolean(slot.is_morning_pickup_only),
      capacity,
      booked,
      remaining,
      isFull: capacity > 0 ? booked >= capacity : true
    };
  });

  return res.json({ ok: true, date: dateISO, slots: results });
});

app.put("/admin/appointment-slot-overrides", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;

  const { slotId, date, capacityLimit } = req.body || {};
  const parsedSlotId = Number(slotId);
  const parsedLimit = Number(capacityLimit);
  const dateISO = parseLocalDateString(date);

  if (!Number.isInteger(parsedSlotId) || parsedSlotId <= 0) {
    return res.status(400).json({ ok: false, message: "slotId must be a positive integer." });
  }
  if (!dateISO) {
    return res.status(400).json({ ok: false, message: "date (YYYY-MM-DD) is required." });
  }
  if (!Number.isInteger(parsedLimit) || parsedLimit <= 0 || parsedLimit > 1000) {
    return res.status(400).json({ ok: false, message: "capacityLimit must be a positive integer (max 1000)." });
  }

  const { error } = await supabaseAdmin
    .from("appointment_slot_overrides")
    .upsert(
      {
        slot_id: parsedSlotId,
        override_date: dateISO,
        capacity_limit: parsedLimit,
        set_by_user_id: null
      },
      { onConflict: "slot_id,override_date" }
    );

  if (error) {
    return res.status(500).json({ ok: false, message: "Unable to save slot capacity override.", detail: error.message });
  }

  return res.json({ ok: true, slotId: parsedSlotId, date: dateISO, capacityLimit: parsedLimit });
});

app.get("/requests", async (req, res) => {
  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  let query = supabaseAdmin.from("service_requests").select("*");
  if (actor.portal === "resident") {
    query = query.eq("resident_user_id", actor.residentUserId);
  } else {
    const requestedResidentUserId = parseResidentUserId(req.query?.residentUserId);
    if (requestedResidentUserId) {
      query = query.eq("resident_user_id", requestedResidentUserId);
    }
  }

  const { data, error } = await query;

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load requests.",
      detail: error.message
    });
  }

  return res.json({
    ok: true,
    requests: (data || [])
      .map(normalizeRequestRow)
      .sort((a, b) => {
        const left = new Date(a.createdAt || 0).getTime();
        const right = new Date(b.createdAt || 0).getTime();
        return right - left;
      })
  });
});

app.get("/requests/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Invalid request id."
    });
  }

  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  const { data, error } = await supabaseAdmin
    .from("service_requests")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load request.",
      detail: error.message
    });
  }

  if (!data) {
    return res.status(404).json({
      ok: false,
      message: "Request not found."
    });
  }

  if (actor.portal === "resident") {
    const ownerId = parseResidentUserId(data.resident_user_id);
    if (!ownerId || ownerId !== actor.residentUserId) {
      return res.status(403).json({
        ok: false,
        message: "You do not have access to this request."
      });
    }
  }

  const requestRow = await normalizeRequestRowWithResident(data);
  return res.json({
    ok: true,
    request: requestRow
  });
});

app.get("/requests/by-reference/:referenceNo", async (req, res) => {
  const referenceNo = sanitizePlainTextField(req.params.referenceNo, 40);
  if (!referenceNo || referenceNo.length < 3) {
    return res.status(400).json({
      ok: false,
      message: "Invalid reference number."
    });
  }

  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  const { data, error } = await supabaseAdmin
    .from("service_requests")
    .select("*")
    .eq("reference_no", referenceNo)
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load request by reference.",
      detail: error.message
    });
  }

  if (!data) {
    return res.status(404).json({
      ok: false,
      message: "Request not found."
    });
  }

  if (actor.portal === "resident") {
    const ownerId = parseResidentUserId(data.resident_user_id);
    if (!ownerId || ownerId !== actor.residentUserId) {
      return res.status(404).json({
        ok: false,
        message: "Request not found."
      });
    }
  }

  const requestRow = await normalizeRequestRowWithResident(data);
  return res.json({
    ok: true,
    request: requestRow
  });
});

app.patch("/requests/:id/status", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;

  const id = Number(req.params.id);
  const { status, note } = req.body || {};
  const safeNote =
    typeof note === "string" && note.trim() ? sanitizePlainTextField(note, MAX_STATUS_NOTE_LEN) : null;
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Invalid request id."
    });
  }

  const allowedStatuses = new Set([
    "Pending",
    "Processing",
    "In Progress",
    "Approved",
    "Ready for Pickup",
    "Completed",
    "Revision Requested",
    "Rejected"
  ]);
  if (!status || !allowedStatuses.has(String(status))) {
    return res.status(400).json({
      ok: false,
      message: "Invalid status value."
    });
  }

  const nextStatus = String(status);
  const { data: existing, error: existingError } = await supabaseAdmin
    .from("service_requests")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (existingError) {
    return res.status(500).json({
      ok: false,
      message: "Unable to update request status.",
      detail: existingError.message
    });
  }
  if (!existing) {
    return res.status(404).json({
      ok: false,
      message: "Request not found."
    });
  }

  const transitionCheck = validateStaffServiceRequestTransition(existing.status, nextStatus);
  if (!transitionCheck.ok) {
    return res.status(400).json({
      ok: false,
      message: transitionCheck.message || "Invalid status transition."
    });
  }

  const nextTimeline = buildNextTimelineFromRow(existing, nextStatus, safeNote || "");

  const updatePayload = { status: nextStatus, status_timeline: nextTimeline };
  const { data, error } = await supabaseAdmin
    .from("service_requests")
    .update(updatePayload)
    .eq("id", id)
    .select("*")
    .maybeSingle();

  if (error) {
    const detail = String(error.message || "");
    const missingCol =
      detail.includes("status_timeline") &&
      (detail.includes("does not exist") ||
        detail.includes("column") ||
        detail.includes("schema cache"));
    return res.status(500).json({
      ok: false,
      message: missingCol
        ? "Database is missing status_timeline. Apply migration 20260504_staff_status_timeline.sql and retry."
        : "Unable to update request status.",
      detail: error.message
    });
  }
  if (!data) {
    return res.status(404).json({
      ok: false,
      message: "Request not found."
    });
  }

  const requestRow = await normalizeRequestRowWithResident(data);
  broadcastRequestEvent({
    type: "status-updated",
    request: requestRow,
    note: safeNote
  });

  return res.json({
    ok: true,
    request: requestRow
  });
});

app.post("/requests", async (req, res) => {
  const auth = await requireResidentPortalUser(req, res);
  if (!auth) return;

  const { title, serviceType, preferredDate, preferredTimeSlot } = req.body || {};

  const safeTitle = sanitizePlainTextField(title, MAX_REQUEST_TITLE_LEN);
  const safeServiceType = sanitizePlainTextField(serviceType, MAX_SERVICE_TYPE_LEN);
  const safePreferredDate = parseLocalDateString(preferredDate);
  const safeTimeSlot = sanitizePlainTextField(preferredTimeSlot, MAX_TIME_SLOT_LEN);

  if (!safeTitle || !safeServiceType || !safePreferredDate || !safeTimeSlot) {
    return res.status(400).json({
      ok: false,
      message: "title, serviceType, preferredDate, and preferredTimeSlot are required. Use YYYY-MM-DD for dates."
    });
  }

  const { data: catalogRows, error: catalogErr } = await supabaseAdmin
    .from("service_catalog")
    .select("id")
    .eq("service_name", safeServiceType)
    .is("archived_at", null)
    .eq("status", "Active")
    .limit(1);

  if (catalogErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to validate service type.",
      detail: catalogErr.message
    });
  }
  const catalogRow = Array.isArray(catalogRows) && catalogRows.length ? catalogRows[0] : null;
  if (!catalogRow) {
    return res.status(400).json({
      ok: false,
      message: "That service is not available for new requests. It may be inactive, under review, or removed."
    });
  }

  const referenceNo = `REQ-${Math.floor(1000 + Math.random() * 9000)}`;
  const resolvedResidentUserId = auth.residentUserId;
  const insertPayload = {
    reference_no: referenceNo,
    title: safeTitle,
    service_type: safeServiceType,
    preferred_date: safePreferredDate,
    preferred_time_slot: safeTimeSlot,
    status: "Pending"
  };
  if (resolvedResidentUserId) {
    insertPayload.resident_user_id = resolvedResidentUserId;
  }

  const { data, error } = await supabaseAdmin
    .from("service_requests")
    .insert(insertPayload)
    .select("*")
    .single();

  if (error) {
    const detail = String(error.message || "");
    const schemaMismatch = detail.includes("resident_user_id") && detail.includes("not-null constraint");
    return res.status(500).json({
      ok: false,
      message: schemaMismatch
        ? "Database schema requires resident_user_id. Apply latest migration and retry."
        : "Unable to submit request.",
      detail: error.message
    });
  }

  const requestRow = normalizeRequestRow(data);
  broadcastRequestEvent({ type: "created", request: requestRow });

  return res.status(201).json({
    ok: true,
    message: "Request submitted successfully.",
    request: requestRow
  });
});

app.delete("/requests/:id", async (req, res) => {
  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Invalid request id."
    });
  }

  const { data: existing, error: loadError } = await supabaseAdmin
    .from("service_requests")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (loadError) {
    return res.status(500).json({
      ok: false,
      message: "Unable to delete request.",
      detail: loadError.message
    });
  }

  if (!existing) {
    return res.status(404).json({
      ok: false,
      message: "Request not found."
    });
  }

  if (actor.portal === "resident") {
    const ownerId = parseResidentUserId(existing.resident_user_id);
    if (!ownerId || ownerId !== actor.residentUserId) {
      return res.status(403).json({
        ok: false,
        message: "You do not have access to this request."
      });
    }
  }

  const { data, error } = await supabaseAdmin
    .from("service_requests")
    .delete()
    .eq("id", id)
    .select("*")
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to delete request.",
      detail: error.message
    });
  }

  if (!data) {
    return res.status(404).json({
      ok: false,
      message: "Request not found."
    });
  }

  const requestRow = normalizeRequestRow(data);
  broadcastRequestEvent({ type: "deleted", request: requestRow });

  return res.json({
    ok: true,
    request: requestRow
  });
});

app.get("/appointments", async (req, res) => {
  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  let query = supabaseAdmin
    .from("appointments")
    .select("*, appointment_slots(label)")
    .order("appointment_date", { ascending: true })
    .order("created_at", { ascending: false });
  if (actor.portal === "resident") {
    query = query.eq("resident_user_id", actor.residentUserId);
  } else {
    const requestedResidentUserId = parseResidentUserId(req.query?.residentUserId);
    if (requestedResidentUserId) {
      query = query.eq("resident_user_id", requestedResidentUserId);
    }
  }
  const { data, error } = await query;

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load appointments.",
      detail: error.message
    });
  }

  return res.json({
    ok: true,
    appointments: (data || []).map(normalizeAppointmentRow)
  });
});

app.get("/appointments/:id", async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Invalid appointment id."
    });
  }

  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  const { data, error } = await supabaseAdmin
    .from("appointments")
    .select("*, appointment_slots(label)")
    .eq("id", id)
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load appointment.",
      detail: error.message
    });
  }

  if (!data) {
    return res.status(404).json({
      ok: false,
      message: "Appointment not found."
    });
  }

  if (actor.portal === "resident") {
    const ownerId = parseResidentUserId(data.resident_user_id);
    if (!ownerId || ownerId !== actor.residentUserId) {
      return res.status(403).json({
        ok: false,
        message: "You do not have access to this appointment."
      });
    }
  }

  const appointmentRow = await normalizeAppointmentRowWithResident(data);
  return res.json({
    ok: true,
    appointment: appointmentRow
  });
});

app.get("/appointments/by-reference/:referenceNo", async (req, res) => {
  const referenceNo = sanitizePlainTextField(req.params.referenceNo, 40);
  if (!referenceNo || referenceNo.length < 3) {
    return res.status(400).json({
      ok: false,
      message: "Invalid appointment reference number."
    });
  }

  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  const { data, error } = await supabaseAdmin
    .from("appointments")
    .select("*, appointment_slots(label)")
    .eq("reference_no", referenceNo)
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load appointment by reference.",
      detail: error.message
    });
  }

  if (!data) {
    return res.status(404).json({
      ok: false,
      message: "Appointment not found."
    });
  }

  if (actor.portal === "resident") {
    const ownerId = parseResidentUserId(data.resident_user_id);
    if (!ownerId || ownerId !== actor.residentUserId) {
      return res.status(404).json({
        ok: false,
        message: "Appointment not found."
      });
    }
  }

  const appointmentRowByRef = await normalizeAppointmentRowWithResident(data);
  return res.json({
    ok: true,
    appointment: appointmentRowByRef
  });
});

app.post("/appointments", async (req, res) => {
  const auth = await requireResidentPortalUser(req, res);
  if (!auth) return;

  const { purpose, appointmentDate, slotId } = req.body || {};

  const safePurpose = sanitizePlainTextField(purpose, MAX_APPOINTMENT_PURPOSE_LEN);
  const safeAppointmentDate = parseLocalDateString(appointmentDate);

  if (!safePurpose || !safeAppointmentDate || slotId === undefined || slotId === null || slotId === "") {
    return res.status(400).json({
      ok: false,
      message: "purpose, appointmentDate, and slotId are required."
    });
  }

  const parsedSlotId = Number(slotId);
  if (!Number.isInteger(parsedSlotId) || parsedSlotId <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Invalid slotId."
    });
  }

  const resolvedResidentUserId = auth.residentUserId;

  const capacity = await getAppointmentSlotCapacityForDate(parsedSlotId, safeAppointmentDate);
  if (!capacity) {
    return res.status(400).json({
      ok: false,
      message: "Selected time slot is unavailable."
    });
  }
  const bookedCount = await countBookedAppointmentsForSlot(parsedSlotId, safeAppointmentDate);
  if (bookedCount === null) {
    return res.status(500).json({
      ok: false,
      message: "Unable to validate slot availability."
    });
  }
  if (bookedCount >= capacity) {
    return res.status(409).json({
      ok: false,
      code: "SLOT_FULL",
      message: "The slot selected is already full, select another slot."
    });
  }

  const referenceNo = `APT-${Math.floor(1000 + Math.random() * 9000)}`;
  const insertPayload = {
    reference_no: referenceNo,
    resident_user_id: resolvedResidentUserId,
    purpose: safePurpose,
    appointment_date: safeAppointmentDate,
    slot_id: parsedSlotId,
    status: "Pending Review"
  };

  const { data, error } = await supabaseAdmin
    .from("appointments")
    .insert(insertPayload)
    .select("*, appointment_slots(label)")
    .single();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to book appointment.",
      detail: error.message
    });
  }

  const appointmentRow = normalizeAppointmentRow(data);
  broadcastAppointmentEvent({ type: "created", appointment: appointmentRow });

  return res.status(201).json({
    ok: true,
    message: "Appointment booked successfully.",
    appointment: appointmentRow
  });
});

app.patch("/appointments/:id/status", async (req, res) => {
  const staffAuth = await requireStaffPortalUser(req, res);
  if (!staffAuth) return;

  const id = Number(req.params.id);
  const { status, note } = req.body || {};
  const safeNote =
    typeof note === "string" && note.trim() ? sanitizePlainTextField(note, MAX_STATUS_NOTE_LEN) : "";
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Invalid appointment id."
    });
  }

  const normalizedInputStatus = String(status || "").trim();
  const mappedStatus = (() => {
    const key = normalizedInputStatus.toLowerCase();
    if (key === "approved") return "Confirmed";
    if (key === "processing") return "Processing";
    if (key === "ready for pickup") return "Ready for Pickup";
    if (key === "in progress") return "Processing";
    if (key === "revision requested") return "Pending Review";
    if (key === "rejected") return "Rejected";
    if (
      key === "completed" ||
      key === "cancelled" ||
      key === "pending review" ||
      key === "confirmed"
    ) {
      return normalizedInputStatus;
    }
    return null;
  })();
  if (!mappedStatus) {
    return res.status(400).json({
      ok: false,
      message: "Invalid status value."
    });
  }

  const { data: existing, error: existingError } = await supabaseAdmin
    .from("appointments")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (existingError) {
    return res.status(500).json({
      ok: false,
      message: "Unable to update appointment status.",
      detail: existingError.message
    });
  }
  if (!existing) {
    return res.status(404).json({
      ok: false,
      message: "Appointment not found."
    });
  }

  const transitionCheck = validateStaffAppointmentTransition(existing.status, mappedStatus);
  if (!transitionCheck.ok) {
    return res.status(400).json({
      ok: false,
      message: transitionCheck.message || "Invalid status transition."
    });
  }

  const nextTimeline = buildNextTimelineFromRow(existing, mappedStatus, safeNote || "");

  const updatePayload = { status: mappedStatus, status_timeline: nextTimeline };
  if (safeNote) {
    updatePayload.notes = safeNote;
  }

  const { data, error } = await supabaseAdmin
    .from("appointments")
    .update(updatePayload)
    .eq("id", id)
    .select("*, appointment_slots(label)")
    .maybeSingle();

  if (error) {
    const detail = String(error.message || "");
    const missingCol =
      detail.includes("status_timeline") &&
      (detail.includes("does not exist") ||
        detail.includes("column") ||
        detail.includes("schema cache"));
    const checkFail =
      detail.includes("violates check constraint") || detail.includes("appointments_status_check");
    return res.status(500).json({
      ok: false,
      message: missingCol
        ? "Database is missing status_timeline or appointment status constraint is outdated. Apply migration 20260504_staff_status_timeline.sql and retry."
        : checkFail
          ? "Database appointment status constraint does not include Processing / Ready for Pickup. Apply migration 20260504_staff_status_timeline.sql and retry."
          : "Unable to update appointment status.",
      detail: error.message
    });
  }
  if (!data) {
    return res.status(404).json({
      ok: false,
      message: "Appointment not found."
    });
  }

  const appointmentRow = await normalizeAppointmentRowWithResident(data);
  broadcastAppointmentEvent({
    type: "status-updated",
    appointment: appointmentRow,
    note: safeNote || null
  });

  return res.json({
    ok: true,
    appointment: appointmentRow
  });
});

app.delete("/appointments/:id", async (req, res) => {
  const actor = await requireStaffOrAuthenticatedResident(req, res);
  if (!actor) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Invalid appointment id."
    });
  }

  const { data: existing, error: loadError } = await supabaseAdmin
    .from("appointments")
    .select("*")
    .eq("id", id)
    .maybeSingle();

  if (loadError) {
    return res.status(500).json({
      ok: false,
      message: "Unable to delete appointment.",
      detail: loadError.message
    });
  }

  if (!existing) {
    return res.status(404).json({
      ok: false,
      message: "Appointment not found."
    });
  }

  if (actor.portal === "resident") {
    const ownerId = parseResidentUserId(existing.resident_user_id);
    if (!ownerId || ownerId !== actor.residentUserId) {
      return res.status(403).json({
        ok: false,
        message: "You do not have access to this appointment."
      });
    }
  }

  const { data, error } = await supabaseAdmin
    .from("appointments")
    .delete()
    .eq("id", id)
    .select("*")
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to delete appointment.",
      detail: error.message
    });
  }

  if (!data) {
    return res.status(404).json({
      ok: false,
      message: "Appointment not found."
    });
  }

  const appointmentRow = normalizeAppointmentRow(data);
  broadcastAppointmentEvent({ type: "deleted", appointment: appointmentRow });

  return res.json({
    ok: true,
    appointment: appointmentRow
  });
});

// --- FAQ retrieval + Groq rewrite (resident chatbot) ---

app.post("/faq/search", faqSearchLimiter, async (req, res) => {
  const rawQuery = req.body?.query ?? req.body?.message ?? "";
  const query = sanitizePlainTextField(rawQuery, MAX_FAQ_SEARCH_QUERY_LEN);
  if (!query) {
    return res.status(400).json({ ok: false, message: "Query is required." });
  }

  let limit = Number(req.body?.limit);
  if (!Number.isInteger(limit) || limit <= 0) {
    limit = FAQ_SEARCH_TOP_LIMIT_DEFAULT;
  }
  limit = Math.min(limit, FAQ_SEARCH_TOP_LIMIT_MAX);

  const result = await retrieveFaqMatchesInternal(query, limit);
  if (!result.ok) {
    return res.status(500).json({
      ok: false,
      message: result.message,
      detail: result.detail
    });
  }

  return res.json({
    ok: true,
    query,
    matches: result.matches,
    bestScore: result.bestScore,
    confidence: result.confidence,
    minScoreUsed: FAQ_SEARCH_MIN_SCORE
  });
});

app.post("/faq/chat", faqChatLimiter, async (req, res) => {
  const rawQuery = req.body?.query ?? req.body?.message ?? "";
  const query = sanitizePlainTextField(rawQuery, MAX_FAQ_SEARCH_QUERY_LEN);
  if (!query) {
    return res.status(400).json({ ok: false, message: "Query is required." });
  }

  let limit = Number(req.body?.limit ?? req.body?.contextLimit);
  if (!Number.isInteger(limit) || limit <= 0) {
    limit = FAQ_SEARCH_TOP_LIMIT_DEFAULT;
  }
  limit = Math.min(limit, FAQ_CHAT_CONTEXT_MAX);

  const retrieved = await retrieveFaqMatchesInternal(query, limit);
  if (!retrieved.ok) {
    return res.status(500).json({
      ok: false,
      message: retrieved.message,
      detail: retrieved.detail
    });
  }

  const noMatchMessage =
    "I don't have the right answer to your question. Visit the barangay hall during office hours or contact the barangay for accurate information.";

  if (!retrieved.matches.length) {
    return res.json({
      ok: true,
      reply: noMatchMessage,
      mode: "no_match",
      confidence: retrieved.confidence,
      sources: []
    });
  }

  const groq = await rewriteFaqWithGroq(query, retrieved.matches);
  const sources = retrieved.matches.map((m) => ({ id: m.id, question: m.question, category: m.category }));

  if (groq.ok) {
    return res.json({
      ok: true,
      reply: groq.text,
      mode: "groq",
      model: groq.model,
      confidence: retrieved.confidence,
      sources
    });
  }

  const topAnswer = retrieved.matches[0].answer;
  const fallbackReply = sanitizeChatReply(topAnswer);
  return res.json({
    ok: true,
    reply: fallbackReply,
    mode: "verbatim_fallback",
    groqUnavailable: groq.reason,
    confidence: retrieved.confidence,
    sources
  });
});

// --- Community announcements (resident bulletin; admin creates) ---

app.get("/announcements", async (_req, res) => {
  const { data, error } = await supabaseAdmin
    .from("community_announcements")
    .select("*")
    .eq("is_active", true)
    .order("created_at", { ascending: false });

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load announcements.",
      detail: error.message
    });
  }

  return res.json({
    ok: true,
    announcements: (data || []).map(normalizeAnnouncementRow)
  });
});

app.get("/resident/announcements", async (req, res) => {
  const auth = await requireResidentPortalUser(req, res);
  if (!auth) return;

  let query = supabaseAdmin.from("community_announcements").select("*").eq("is_active", true);
  const filterRole = String(req.query?.postedByRole ?? "").trim();
  if (filterRole === "admin") query = query.eq("posted_by_role", "admin");
  query = query.order("created_at", { ascending: false });

  const { data, error } = await query;
  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load announcements.",
      detail: error.message
    });
  }
  return res.json({
    ok: true,
    announcements: (data || []).map(normalizeAnnouncementRow)
  });
});

app.post("/admin/announcements", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;

  const { category, title, body } = req.body || {};
  const safeTitle = sanitizePlainTextField(title, MAX_ANNOUNCEMENT_TITLE_LEN);
  const safeBody = sanitizePlainTextField(body, MAX_ANNOUNCEMENT_BODY_LEN);
  const safeCategory = sanitizePlainTextField(category || "Community News", MAX_ANNOUNCEMENT_CATEGORY_LEN);

  if (!safeTitle) {
    return res.status(400).json({ ok: false, message: "Title is required." });
  }
  if (!safeBody) {
    return res.status(400).json({ ok: false, message: "Announcement details are required." });
  }

  const insertPayload = {
    category: safeCategory || "Community News",
    title: safeTitle,
    body: safeBody,
    is_active: true,
    posted_by_role: auth.profile?.role ?? null
  };

  const { data, error } = await supabaseAdmin
    .from("community_announcements")
    .insert(insertPayload)
    .select("*")
    .single();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to post announcement.",
      detail: error.message
    });
  }

  const createdRow = normalizeAnnouncementRow(data);
  broadcastAnnouncementEvent({ type: "created", announcement: createdRow });

  return res.status(201).json({
    ok: true,
    message: "Announcement posted.",
    announcement: createdRow
  });
});

/** List all announcements (including inactive) for admin reporting table. */
app.get("/admin/announcements", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({ ok: false, message: "Admin role required to list announcements." });
  }

  const { data, error } = await supabaseAdmin
    .from("community_announcements")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load announcements.",
      detail: error.message
    });
  }

  return res.json({
    ok: true,
    announcements: (data || []).map(normalizeAnnouncementRow)
  });
});

/** Permanently remove an announcement (admin only). */
app.delete("/admin/announcements/:id", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({
      ok: false,
      message: "Admin role required to delete announcements."
    });
  }

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ ok: false, message: "Invalid announcement id." });
  }

  const { data: existing, error: findErr } = await supabaseAdmin
    .from("community_announcements")
    .select("id")
    .eq("id", id)
    .maybeSingle();

  if (findErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to verify announcement.",
      detail: findErr.message
    });
  }
  if (!existing) {
    return res.status(404).json({ ok: false, message: "Announcement not found." });
  }

  const { error: delErr } = await supabaseAdmin.from("community_announcements").delete().eq("id", id);

  if (delErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to delete announcement.",
      detail: delErr.message
    });
  }

  broadcastAnnouncementEvent({ type: "deleted", id });

  return res.json({ ok: true, message: "Announcement deleted." });
});

// --- Admin reports & analytics ---

function pctCompleted(completed, total) {
  const t = Number(total);
  const c = Number(completed);
  if (!Number.isFinite(t) || t <= 0) return 0;
  if (!Number.isFinite(c) || c <= 0) return 0;
  return Math.round((c / t) * 1000) / 10;
}

/** Inclusive office-hour window for peak-hours chart (matches admin reports UI). */
const ANALYTICS_HOURLY_CHART_START_HOUR = 9;
const ANALYTICS_HOURLY_CHART_END_HOUR = 17;

/** Parse slot label, time range, or HHMM `slot_code` to hour 0–23 (start of window). */
function parseClockToHour24(input) {
  const raw = String(input ?? "").trim();
  if (!raw) return null;
  const firstSegment = raw.split(/\s*[–-]\s*/u)[0].trim();
  if (/\b(AM|PM)\b/i.test(firstSegment)) {
    const m = firstSegment.match(/\b(\d{1,2})(?::(\d{2}))?\s*(AM|PM)\b/i);
    if (!m) return null;
    let h = parseInt(m[1], 10);
    const ap = m[3].toUpperCase();
    if (ap === "PM" && h !== 12) h += 12;
    if (ap === "AM" && h === 12) h = 0;
    if (!Number.isInteger(h) || h < 0 || h > 23) return null;
    return h;
  }
  const digitRun = raw.replace(/\D/g, "");
  if (digitRun.length >= 3 && digitRun.length <= 4 && /^\d+$/.test(digitRun)) {
    const pad = digitRun.padStart(4, "0").slice(-4);
    const h = parseInt(pad.slice(0, 2), 10);
    if (Number.isInteger(h) && h >= 0 && h <= 23) return h;
  }
  return null;
}

function hourFitsAnalyticsChart(hour24) {
  if (!Number.isInteger(hour24)) return null;
  if (hour24 < ANALYTICS_HOURLY_CHART_START_HOUR || hour24 > ANALYTICS_HOURLY_CHART_END_HOUR) return null;
  return hour24;
}

function formatAnalyticsHourAxisLabel(hour24) {
  if (hour24 === 12) return "12 NN";
  if (hour24 < 12) return `${hour24} AM`;
  return `${hour24 - 12} PM`;
}

function appointmentPreferredStartHour24(row) {
  const rawSlot = row?.appointment_slots;
  const slot = Array.isArray(rawSlot) ? rawSlot[0] : rawSlot;
  if (slot && slot.slot_code != null && String(slot.slot_code).trim()) {
    const fromCode = parseClockToHour24(String(slot.slot_code).trim());
    if (fromCode !== null) return fromCode;
  }
  if (slot && slot.label) {
    return parseClockToHour24(String(slot.label));
  }
  return null;
}

app.get("/admin/analytics/hourly-demand", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({
      ok: false,
      message: "Admin role required to view hourly demand analytics."
    });
  }

  const fromDate = parseLocalDateString(req.query?.from);
  const toDate = parseLocalDateString(req.query?.to);

  let reqQuery = supabaseAdmin
    .from("service_requests")
    .select("id, preferred_time_slot, preferred_date")
    .limit(10000);
  if (fromDate) reqQuery = reqQuery.gte("preferred_date", fromDate);
  if (toDate) reqQuery = reqQuery.lte("preferred_date", toDate);

  let apptQuery = supabaseAdmin
    .from("appointments")
    .select("id, appointment_date, status, appointment_slots ( slot_code, label )")
    .limit(10000);
  if (fromDate) apptQuery = apptQuery.gte("appointment_date", fromDate);
  if (toDate) apptQuery = apptQuery.lte("appointment_date", toDate);

  const [reqRes, apptRes] = await Promise.all([reqQuery, apptQuery]);

  if (reqRes.error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load service requests for hourly demand.",
      detail: reqRes.error.message
    });
  }
  if (apptRes.error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load appointments for hourly demand.",
      detail: apptRes.error.message
    });
  }

  const buckets = [];
  for (let h = ANALYTICS_HOURLY_CHART_START_HOUR; h <= ANALYTICS_HOURLY_CHART_END_HOUR; h += 1) {
    buckets.push({
      hour: h,
      label: formatAnalyticsHourAxisLabel(h),
      requests: 0,
      appointments: 0,
      total: 0
    });
  }
  const byHour = new Map(buckets.map((b) => [b.hour, b]));

  let unbucketedRequests = 0;
  for (const row of reqRes.data || []) {
    const hour24 = hourFitsAnalyticsChart(parseClockToHour24(row.preferred_time_slot));
    if (hour24 === null) {
      unbucketedRequests += 1;
      continue;
    }
    const b = byHour.get(hour24);
    b.requests += 1;
    b.total += 1;
  }

  let unbucketedAppointments = 0;
  const skipApptStatus = new Set(["Cancelled", "Rejected"]);
  for (const row of apptRes.data || []) {
    if (skipApptStatus.has(String(row.status || ""))) continue;
    const hour24 = hourFitsAnalyticsChart(appointmentPreferredStartHour24(row));
    if (hour24 === null) {
      unbucketedAppointments += 1;
      continue;
    }
    const b = byHour.get(hour24);
    b.appointments += 1;
    b.total += 1;
  }

  const maxTotal = buckets.reduce((m, b) => Math.max(m, b.total), 0);
  let peakHour = null;
  for (const b of buckets) {
    if (b.total <= 0) continue;
    if (peakHour === null || b.total > peakHour.total) peakHour = b;
  }

  return res.json({
    ok: true,
    chartStartHour: ANALYTICS_HOURLY_CHART_START_HOUR,
    chartEndHour: ANALYTICS_HOURLY_CHART_END_HOUR,
    dateFilter: {
      from: fromDate,
      to: toDate
    },
    buckets,
    maxTotal,
    peakHour: peakHour
      ? {
          hour: peakHour.hour,
          label: peakHour.label,
          total: peakHour.total,
          requests: peakHour.requests,
          appointments: peakHour.appointments
        }
      : null,
    unbucketedRequests,
    unbucketedAppointments
  });
});

app.get("/admin/analytics/summary", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({
      ok: false,
      message: "Admin role required to view analytics."
    });
  }

  const [reqAll, reqDone, apptAll, apptDone] = await Promise.all([
    supabaseAdmin.from("service_requests").select("id", { count: "exact", head: true }),
    supabaseAdmin.from("service_requests").select("id", { count: "exact", head: true }).eq("status", "Completed"),
    supabaseAdmin.from("appointments").select("id", { count: "exact", head: true }),
    supabaseAdmin.from("appointments").select("id", { count: "exact", head: true }).eq("status", "Completed")
  ]);

  if (reqAll.error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to count service requests.",
      detail: reqAll.error.message
    });
  }
  if (reqDone.error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to count completed service requests.",
      detail: reqDone.error.message
    });
  }
  if (apptAll.error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to count appointments.",
      detail: apptAll.error.message
    });
  }
  if (apptDone.error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to count completed appointments.",
      detail: apptDone.error.message
    });
  }

  const requestsTotal = typeof reqAll.count === "number" ? reqAll.count : 0;
  const requestsCompleted = typeof reqDone.count === "number" ? reqDone.count : 0;
  const appointmentsTotal = typeof apptAll.count === "number" ? apptAll.count : 0;
  const appointmentsCompleted = typeof apptDone.count === "number" ? apptDone.count : 0;

  const totalRequestsAndAppointments = requestsTotal + appointmentsTotal;
  const completedTotal = requestsCompleted + appointmentsCompleted;
  const overallCompletionRatePercent = pctCompleted(completedTotal, totalRequestsAndAppointments);

  let activeResidents = 0;
  const usersCount = await supabaseAdmin
    .from("users")
    .select("id", { count: "exact", head: true })
    .eq("role", "resident")
    .eq("is_active", true);

  if (!usersCount.error && typeof usersCount.count === "number") {
    activeResidents = usersCount.count;
  } else {
    const profRes = await supabaseAdmin
      .from("profiles")
      .select("email", { count: "exact", head: true })
      .eq("role", "resident");
    if (profRes.error) {
      return res.status(500).json({
        ok: false,
        message: "Unable to count active residents.",
        detail: profRes.error.message
      });
    }
    activeResidents = typeof profRes.count === "number" ? profRes.count : 0;
  }

  return res.json({
    ok: true,
    totalRequestsAndAppointments,
    requestsTotal,
    appointmentsTotal,
    requestsCompleted,
    appointmentsCompleted,
    overallCompletionRatePercent,
    requestsCompletionRatePercent: pctCompleted(requestsCompleted, requestsTotal),
    appointmentsCompletionRatePercent: pctCompleted(appointmentsCompleted, appointmentsTotal),
    activeResidents
  });
});

function sanitizeSummaryForDecisionInsight(s) {
  if (!s || typeof s !== "object") return {};
  return {
    totalRequestsAndAppointments: s.totalRequestsAndAppointments,
    requestsTotal: s.requestsTotal,
    appointmentsTotal: s.appointmentsTotal,
    requestsCompleted: s.requestsCompleted,
    appointmentsCompleted: s.appointmentsCompleted,
    overallCompletionRatePercent: s.overallCompletionRatePercent,
    requestsCompletionRatePercent: s.requestsCompletionRatePercent,
    appointmentsCompletionRatePercent: s.appointmentsCompletionRatePercent,
    activeResidents: s.activeResidents
  };
}

function sanitizeHourlyDemandForDecisionInsight(h) {
  if (!h || typeof h !== "object") {
    return {
      chartStartHour: null,
      chartEndHour: null,
      maxTotal: 0,
      peakHour: null,
      buckets: [],
      unbucketedRequests: 0,
      unbucketedAppointments: 0,
      dateFilter: null
    };
  }
  const buckets = Array.isArray(h.buckets)
    ? h.buckets.map((b) => ({
        hour: b.hour,
        label: b.label,
        requests: b.requests,
        appointments: b.appointments,
        total: b.total
      }))
    : [];
  return {
    chartStartHour: h.chartStartHour,
    chartEndHour: h.chartEndHour,
    maxTotal: h.maxTotal,
    peakHour: h.peakHour ?? null,
    buckets,
    unbucketedRequests: h.unbucketedRequests,
    unbucketedAppointments: h.unbucketedAppointments,
    dateFilter: h.dateFilter ?? null
  };
}

function buildBarangayDecisionInsightFallback(summary, hourlyDemand) {
  const parts = [];
  const overall = Number(summary?.overallCompletionRatePercent);
  const total = Number(summary?.totalRequestsAndAppointments) || 0;
  const reqPct = Number(summary?.requestsCompletionRatePercent);
  const apptPct = Number(summary?.appointmentsCompletionRatePercent);

  if (Number.isFinite(overall) && total > 0 && overall < 65) {
    parts.push(
      `Overall completion is about ${overall}%, which is low for steady barangay operations. Prioritise clearing the oldest pending requests, verify resident contact details, and hold a brief daily triage so nothing stalls more than a few days.`
    );
  } else if (Number.isFinite(overall) && total > 0) {
    parts.push(
      `Overall completion is about ${overall}%. Keep documenting turnaround times and watch for any single service type dragging the average down.`
    );
  }

  if (
    Number.isFinite(reqPct) &&
    Number.isFinite(apptPct) &&
    total > 0 &&
    reqPct + 8 < apptPct
  ) {
    parts.push(
      `Document request completion (${reqPct}%) is noticeably weaker than appointment completion (${apptPct}%); consider dedicating more staff time to request processing or simplifying documentary requirements where policy allows.`
    );
  }

  const peak = hourlyDemand?.peakHour;
  const maxT = Number(hourlyDemand?.maxTotal) || 0;
  if (peak && Number(peak.total) > 0 && maxT > 0) {
    const concentration = peak.total / maxT;
    if (concentration >= 0.42 && peak.total >= 5) {
      parts.push(
        `Hourly demand is concentrated around ${peak.label} (${peak.total} requests and appointments in that hour). Adding counter staff or staggering breaks during that window usually reduces queues more than uniform staffing all day.`
      );
    } else {
      parts.push(
        `The busiest hour is ${peak.label} with ${peak.total} combined bookings; align clerk breaks so coverage stays strong in that window.`
      );
    }
  }

  const ub =
    (Number(hourlyDemand?.unbucketedRequests) || 0) + (Number(hourlyDemand?.unbucketedAppointments) || 0);
  if (ub > 0) {
    parts.push(
      `${ub} booking(s) could not be placed on the hourly chart; standardising preferred time labels in the portal will improve future staffing decisions.`
    );
  }

  if (!parts.length) {
    return "Collect a few more weeks of bookings with consistent time slots, then revisit staffing. There is not enough structured volume yet for a strong barangay-specific recommendation.";
  }
  return parts.join(" ");
}

async function groqBarangayDecisionInsight(context) {
  const apiKey = process.env.GROQ_API_KEY;
  const model = process.env.GROQ_MODEL || "llama-3.3-70b-versatile";
  if (!apiKey) return null;

  const system = `You are an experienced advisor helping a Philippine BARANGAY (local government unit) front office deliver citizen services: clearances, certificates, appointments for pickup, and similar desk work.

You receive JSON with:
- summary: counts of service requests and appointments, completion rates (percent), and active portal residents.
- hourlyDemand: per-hour totals from 9 AM to 5 PM combining residents' preferred time on service requests and booked appointment slot start times; includes peakHour and unbucketed counts.

Write exactly ONE paragraph in clear English (100–220 words) with practical recommendations for the Barangay Captain, Secretary, or clerks: staffing at peak windows, reducing backlog when completion is low, communicating with residents, slot or queue policy, or follow-up. Use ONLY numbers and facts from the JSON; never invent statistics. If data is very sparse, say so briefly and suggest what to track next. Plain text only; no markdown, bullets, or headings.`;

  const userMsg = `Analytics JSON:\n${JSON.stringify(context, null, 2)}`;

  const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: system },
        { role: "user", content: userMsg }
      ],
      temperature: 0.35,
      max_tokens: 500
    })
  });

  if (!res.ok) {
    const t = await res.text().catch(() => "");
    throw new Error(`Groq HTTP ${res.status}: ${t.slice(0, 600)}`);
  }

  const data = await res.json();
  const text = data?.choices?.[0]?.message?.content?.trim();
  return typeof text === "string" && text.length ? text : null;
}

/** AI-assisted barangay operations insight (Groq); falls back to heuristics if key missing or Groq fails. */
app.post(
  "/admin/analytics/decision-insight",
  adminAnalyticsDecisionInsightLimiter,
  async (req, res) => {
    const auth = await requireStaffPortalUser(req, res);
    if (!auth) return;
    if (auth.profile.role !== "admin") {
      return res.status(403).json({
        ok: false,
        message: "Admin role required to generate decision insights."
      });
    }

    const { summary: rawSummary, hourlyDemand: rawHourly } = req.body || {};
    if (!rawSummary || typeof rawSummary !== "object" || !rawHourly || typeof rawHourly !== "object") {
      return res.status(400).json({
        ok: false,
        message:
          "JSON body must include `summary` and `hourlyDemand` objects (responses from GET /admin/analytics/summary and GET /admin/analytics/hourly-demand)."
      });
    }

    const context = {
      summary: sanitizeSummaryForDecisionInsight(rawSummary),
      hourlyDemand: sanitizeHourlyDemandForDecisionInsight(rawHourly)
    };

    let insight = null;
    let source = "groq";
    try {
      if (process.env.GROQ_API_KEY) {
        insight = await groqBarangayDecisionInsight(context);
      }
    } catch (err) {
      console.warn("[admin/analytics/decision-insight] Groq error:", err?.message || err);
    }

    if (!insight) {
      insight = buildBarangayDecisionInsightFallback(context.summary, context.hourlyDemand);
      source = "fallback";
    }

    return res.json({
      ok: true,
      insight,
      source,
      groqConfigured: Boolean(process.env.GROQ_API_KEY)
    });
  }
);

// --- Admin user profiles (User & Role management) ---

app.get("/admin/profiles", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({ ok: false, message: "Admin role required to list all users." });
  }

  const { data, error } = await supabaseAdmin
    .from("profiles")
    .select("email, full_name, role, created_at, staff_permissions, resident_self_registered")
    .not("role", "eq", "admin")
    .not("role", "eq", "system-admin")
    .order("full_name", { ascending: true });

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load user profiles.",
      detail: error.message
    });
  }

  return res.json({
    ok: true,
    profiles: (data || []).map((row) => {
      const profile = {
        email: row.email,
        fullName: row.full_name,
        role: row.role,
        createdAt: row.created_at,
        residentSelfRegistered: row.role === "resident" && Boolean(row.resident_self_registered)
      };
      if (row.role === "staff") {
        profile.staffPermissions = normalizeStaffPermissionsFromDb(row.staff_permissions);
      }
      return profile;
    })
  });
});

/** Barangay admin creates a staff Supabase Auth user + profile with page permissions (JSON on profiles). */
app.post("/admin/staff", adminStaffCreateLimiter, async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({
      ok: false,
      message: "Only barangay administrators can create staff accounts."
    });
  }

  const body = req.body || {};
  const { fullName, email, password } = body;
  const normalizedEmail = normalizeEmail(email);
  const safeFullName = sanitizeFullNameForStorage(fullName);
  const safePassword = String(password || "");
  const perms = normalizeStaffPermissionsFromBody(body.permissions ?? body);

  if (!safeFullName || !normalizedEmail || !safePassword) {
    return res.status(400).json({
      ok: false,
      message: "fullName, email, and password are required."
    });
  }

  if (!isValidEmailFormat(normalizedEmail)) {
    return res.status(400).json({
      ok: false,
      message: "Please enter a valid email address."
    });
  }

  if (safePassword.length < 8) {
    return res.status(400).json({
      ok: false,
      message: "Password must be at least 8 characters long."
    });
  }

  if (safePassword.length > MAX_PASSWORD_LEN) {
    return res.status(400).json({
      ok: false,
      message: `Password must be at most ${MAX_PASSWORD_LEN} characters.`
    });
  }

  const { data: existingProfile, error: existingErr } = await supabaseAdmin
    .from("profiles")
    .select("email")
    .eq("email", normalizedEmail)
    .maybeSingle();

  if (existingErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to verify email availability.",
      detail: existingErr.message
    });
  }

  if (existingProfile) {
    return res.status(409).json({
      ok: false,
      message: "An account with this email already exists."
    });
  }

  const { data: created, error: createErr } = await supabaseAdmin.auth.admin.createUser({
    email: normalizedEmail,
    password: safePassword,
    email_confirm: true,
    user_metadata: {
      full_name: safeFullName,
      role: "staff"
    }
  });

  if (createErr || !created?.user?.id) {
    const msg = String(createErr?.message || "Unable to create staff login.");
    const lower = msg.toLowerCase();
    if (
      lower.includes("already") ||
      lower.includes("registered") ||
      lower.includes("exists") ||
      lower.includes("duplicate") ||
      lower.includes("unique")
    ) {
      return res.status(409).json({
        ok: false,
        message: "An account with this email already exists."
      });
    }
    return res.status(400).json({
      ok: false,
      message: msg
    });
  }

  const upsertPayload = {
    email: normalizedEmail,
    full_name: safeFullName,
    role: "staff",
    staff_permissions: perms
  };

  const { error: profErr } = await supabaseAdmin.from("profiles").upsert(upsertPayload, { onConflict: "email" });

  if (profErr) {
    await supabaseAdmin.auth.admin.deleteUser(created.user.id);
    return res.status(500).json({
      ok: false,
      message: "Staff login was created but saving the profile failed. The partial auth user was removed.",
      detail: profErr.message
    });
  }

  return res.status(201).json({
    ok: true,
    message: "Staff account created.",
    user: {
      email: normalizedEmail,
      fullName: safeFullName,
      role: "staff",
      staffPermissions: perms
    }
  });
});

/** Update saved page permissions for an existing staff profile (admin only). */
app.patch("/admin/staff/permissions", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({
      ok: false,
      message: "Only barangay administrators can update staff permissions."
    });
  }

  const normalizedEmail = normalizeEmail(req.body?.email ?? "");
  if (!normalizedEmail || !isValidEmailFormat(normalizedEmail)) {
    return res.status(400).json({
      ok: false,
      message: "A valid staff email is required."
    });
  }

  const perms = normalizeStaffPermissionsFromBody(req.body?.permissions ?? req.body);

  const { data: profile, error: loadErr } = await supabaseAdmin
    .from("profiles")
    .select("email, role")
    .eq("email", normalizedEmail)
    .maybeSingle();

  if (loadErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load profile.",
      detail: loadErr.message
    });
  }

  if (!profile || profile.role !== "staff") {
    return res.status(404).json({
      ok: false,
      message: "No staff account found for that email."
    });
  }

  const { error: upErr } = await supabaseAdmin
    .from("profiles")
    .update({ staff_permissions: perms })
    .eq("email", normalizedEmail)
    .eq("role", "staff");

  if (upErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to update staff permissions.",
      detail: upErr.message
    });
  }

  return res.json({
    ok: true,
    message: "Staff permissions updated.",
    staffPermissions: perms
  });
});

async function findAuthUserIdByEmail(normalizedEmail) {
  let page = 1;
  const perPage = 200;
  for (let attempt = 0; attempt < 50; attempt++) {
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ page, perPage });
    if (error) return { id: null, error };
    const hit = data.users.find((u) => normalizeEmail(u.email) === normalizedEmail);
    if (hit?.id) return { id: hit.id, error: null };
    if (!data.users?.length || data.users.length < perPage) break;
    page += 1;
  }
  return { id: null, error: null };
}

/** Remove profile + app user row + Supabase Auth user (admin only; cannot delete self or other admins). */
app.post("/admin/profiles/delete", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({ ok: false, message: "Admin role required to delete users." });
  }

  const email = normalizeEmail(req.body?.email ?? "");
  if (!email || !isValidEmailFormat(email)) {
    return res.status(400).json({ ok: false, message: "A valid email is required." });
  }

  if (normalizeEmail(auth.profile.email) === email) {
    return res.status(400).json({ ok: false, message: "You cannot delete your own account." });
  }

  const { data: profile, error: profLoadErr } = await supabaseAdmin
    .from("profiles")
    .select("email, role")
    .eq("email", email)
    .maybeSingle();

  if (profLoadErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load profile.",
      detail: profLoadErr.message
    });
  }

  if (!profile) {
    return res.status(404).json({ ok: false, message: "No profile found for that email." });
  }

  if (profile.role === "admin") {
    return res.status(403).json({ ok: false, message: "Deleting admin accounts is not allowed." });
  }

  const { id: authUserId, error: authLookupErr } = await findAuthUserIdByEmail(email);
  if (authLookupErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to look up auth user.",
      detail: authLookupErr.message
    });
  }

  if (profile.role === "resident") {
    const { data: userRow } = await supabaseAdmin.from("users").select("id").eq("email", email).maybeSingle();
    if (userRow?.id) {
      const { count, error: reqErr } = await supabaseAdmin
        .from("service_requests")
        .select("id", { count: "exact", head: true })
        .eq("resident_user_id", userRow.id);
      if (!reqErr && typeof count === "number" && count > 0) {
        return res.status(409).json({
          ok: false,
          message:
            "This resident has service requests on file. Resolve or remove those records before deleting the account."
        });
      }
    }
  }

  const { error: usersDelErr } = await supabaseAdmin.from("users").delete().eq("email", email);
  if (usersDelErr) {
    const msg = String(usersDelErr.message || "");
    if (/foreign key|violates/i.test(msg)) {
      return res.status(409).json({
        ok: false,
        message: "This account cannot be deleted while related records still reference it.",
        detail: usersDelErr.message
      });
    }
    return res.status(500).json({
      ok: false,
      message: "Unable to remove linked user record.",
      detail: usersDelErr.message
    });
  }

  const { error: profDelErr } = await supabaseAdmin.from("profiles").delete().eq("email", email);
  if (profDelErr) {
    return res.status(500).json({
      ok: false,
      message: "Unable to delete profile.",
      detail: profDelErr.message
    });
  }

  if (authUserId) {
    const { error: authDelErr } = await supabaseAdmin.auth.admin.deleteUser(authUserId);
    if (authDelErr) {
      return res.status(500).json({
        ok: false,
        message: "Profile removed but deleting the Supabase Auth user failed. Remove the auth user manually if needed.",
        detail: authDelErr.message
      });
    }
  }

  return res.json({ ok: true, message: "Account deleted." });
});

function getLocalCalendarMonthStartEndIso() {
  const now = new Date();
  const y = now.getFullYear();
  const m = now.getMonth();
  const start = new Date(y, m, 1, 0, 0, 0, 0);
  const end = new Date(y, m + 1, 0, 23, 59, 59, 999);
  return { monthStartIso: start.toISOString(), monthEndIso: end.toISOString() };
}

/** Inclusive YYYY-MM-DD bounds for the current local calendar month (for date columns). */
function getLocalCalendarMonthDateStrings() {
  const now = new Date();
  const y = now.getFullYear();
  const m = now.getMonth();
  const pad = (n) => String(n).padStart(2, "0");
  const monthStartDate = `${y}-${pad(m + 1)}-01`;
  const lastDay = new Date(y, m + 1, 0).getDate();
  const monthEndDate = `${y}-${pad(m + 1)}-${pad(lastDay)}`;
  return { monthStartDate, monthEndDate };
}

function currentMonthYearLabel() {
  return new Date().toLocaleString("en-US", { month: "long", year: "numeric" });
}

/** Overview metrics for the admin service management dashboard (catalog table, users, month volume, announcements). */
app.get("/admin/service-dashboard/summary", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;
  if (auth.profile.role !== "admin") {
    return res.status(403).json({ ok: false, message: "Admin role required to view this summary." });
  }

  const { monthStartIso, monthEndIso } = getLocalCalendarMonthStartEndIso();
  const { monthStartDate, monthEndDate } = getLocalCalendarMonthDateStrings();

  const [catalogRes, staffRes, residentRes, reqMonthRes, apptMonthRes, annRes] = await Promise.all([
    supabaseAdmin.from("service_catalog").select("id", { count: "exact", head: true }).is("archived_at", null),
    supabaseAdmin.from("profiles").select("email", { count: "exact", head: true }).eq("role", "staff"),
    supabaseAdmin.from("profiles").select("email", { count: "exact", head: true }).eq("role", "resident"),
    // Use preferred_date (always present); some DBs omit created_at on service_requests, which breaks timestamptz filters.
    supabaseAdmin
      .from("service_requests")
      .select("id", { count: "exact", head: true })
      .gte("preferred_date", monthStartDate)
      .lte("preferred_date", monthEndDate),
    supabaseAdmin
      .from("appointments")
      .select("id", { count: "exact", head: true })
      .gte("created_at", monthStartIso)
      .lte("created_at", monthEndIso),
    supabaseAdmin.from("community_announcements").select("id", { count: "exact", head: true })
  ]);

  const namedErrors = [
    ["service catalog", catalogRes.error],
    ["staff count", staffRes.error],
    ["resident count", residentRes.error],
    ["requests (month)", reqMonthRes.error],
    ["appointments (month)", apptMonthRes.error],
    ["announcements", annRes.error]
  ];
  const failed = namedErrors.find(([, err]) => err);
  if (failed) {
    return res.status(500).json({
      ok: false,
      message: `Unable to load dashboard summary (${failed[0]}).`,
      detail: failed[1].message
    });
  }

  const totalServices = typeof catalogRes.count === "number" ? catalogRes.count : 0;
  const staffCount = typeof staffRes.count === "number" ? staffRes.count : 0;
  const residentCount = typeof residentRes.count === "number" ? residentRes.count : 0;
  const monthRequestsCount = typeof reqMonthRes.count === "number" ? reqMonthRes.count : 0;
  const monthAppointmentsCount = typeof apptMonthRes.count === "number" ? apptMonthRes.count : 0;
  const totalAnnouncementsPosted = typeof annRes.count === "number" ? annRes.count : 0;

  return res.json({
    ok: true,
    totalServices,
    staffCount,
    residentCount,
    staffAndResidentsTotal: staffCount + residentCount,
    monthRequestsCount,
    monthAppointmentsCount,
    monthRequestsAndAppointmentsTotal: monthRequestsCount + monthAppointmentsCount,
    monthLabel: currentMonthYearLabel(),
    monthRangeStartIso: monthStartIso,
    monthRangeEndIso: monthEndIso,
    totalAnnouncementsPosted
  });
});

// --- Admin service catalog ---

app.get("/admin/service-catalog", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;

  const includeArchived = String(req.query?.includeArchived || "") === "1";
  let query = supabaseAdmin.from("service_catalog").select("*").order("created_at", { ascending: true });
  if (!includeArchived) {
    query = query.is("archived_at", null);
  }

  const { data, error } = await query;

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to load service catalog.",
      detail: error.message
    });
  }

  return res.json({
    ok: true,
    services: (data || []).map(normalizeServiceCatalogRow)
  });
});

app.post("/admin/service-catalog", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;

  const { name, requiredDocuments, processingTime, status } = req.body || {};
  if (!name || !String(name).trim()) {
    return res.status(400).json({ ok: false, message: "Service name is required." });
  }

  const allowedStatuses = new Set(["Active", "Under Review", "Inactive"]);
  const nextStatus = allowedStatuses.has(String(status)) ? String(status) : "Active";

  const insertPayload = {
    service_name: String(name).trim(),
    required_documents: String(requiredDocuments ?? "").trim(),
    processing_time: String(processingTime || "1-2 Days").trim(),
    status: nextStatus,
    archived_at: null
  };

  const { data, error } = await supabaseAdmin
    .from("service_catalog")
    .insert(insertPayload)
    .select("*")
    .single();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to create service.",
      detail: error.message
    });
  }

  return res.status(201).json({
    ok: true,
    service: normalizeServiceCatalogRow(data)
  });
});

app.patch("/admin/service-catalog/:id", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ ok: false, message: "Invalid service id." });
  }

  const { name, requiredDocuments, processingTime, status } = req.body || {};
  const updatePayload = {};
  if (typeof name === "string" && name.trim()) updatePayload.service_name = name.trim();
  if (typeof requiredDocuments === "string") updatePayload.required_documents = requiredDocuments.trim();
  if (typeof processingTime === "string") updatePayload.processing_time = processingTime.trim();
  if (typeof status === "string") {
    const allowedStatuses = new Set(["Active", "Under Review", "Inactive"]);
    if (allowedStatuses.has(status)) updatePayload.status = status;
  }

  if (!Object.keys(updatePayload).length) {
    return res.status(400).json({ ok: false, message: "No valid fields to update." });
  }

  const { data, error } = await supabaseAdmin
    .from("service_catalog")
    .update(updatePayload)
    .eq("id", id)
    .select("*")
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to update service.",
      detail: error.message
    });
  }

  if (!data) {
    return res.status(404).json({ ok: false, message: "Service not found." });
  }

  return res.json({
    ok: true,
    service: normalizeServiceCatalogRow(data)
  });
});

app.post("/admin/service-catalog/:id/archive", async (req, res) => {
  const auth = await requireStaffPortalUser(req, res);
  if (!auth) return;

  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({ ok: false, message: "Invalid service id." });
  }

  const { data, error } = await supabaseAdmin
    .from("service_catalog")
    .update({ archived_at: new Date().toISOString() })
    .eq("id", id)
    .is("archived_at", null)
    .select("*")
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to archive service.",
      detail: error.message
    });
  }

  if (!data) {
    return res.status(404).json({ ok: false, message: "Service not found or already archived." });
  }

  return res.json({
    ok: true,
    service: normalizeServiceCatalogRow(data)
  });
});

// Start the API server on the configured port (explicit http.Server for error + diagnostics).
const server = http.createServer(app);

server.on("error", (err) => {
  console.error("[backend] Server failed to start:", err.message);
  if (err.code === "EADDRINUSE") {
    console.error(`[backend] Port ${port} is already in use. Stop the other process or set PORT in .env.`);
  }
  process.exit(1);
});

server.listen(port, "0.0.0.0", () => {
  const addr = server.address();
  const where =
    typeof addr === "object" && addr
      ? `http://127.0.0.1:${addr.port} (bound ${addr.address})`
      : `http://localhost:${port}`;
  console.log(`Backend running on ${where}`);
  console.log("[backend] Leave this terminal open while developing. Press Ctrl+C to stop.");
});

function gracefulShutdown(signal) {
  intentionalShutdown = true;
  console.log(`[backend] ${signal} received — closing HTTP server...`);
  server.close(() => {
    console.log("[backend] HTTP server closed.");
    process.exit(0);
  });
}

process.once("SIGINT", () => gracefulShutdown("SIGINT"));
process.once("SIGTERM", () => gracefulShutdown("SIGTERM"));
