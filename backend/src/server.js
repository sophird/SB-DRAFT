require("dotenv").config();

const http = require("http");
const express = require("express");
const cors = require("cors");
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
app.use(express.json());

const supabaseAdmin = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);
const supabaseAuth = createClient(
  process.env.SUPABASE_URL || "",
  process.env.SUPABASE_ANON_KEY || ""
);

const requestEventClients = new Set();

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

// Return basic API status and whether Supabase env vars are present.
app.get("/health", async (_req, res) => {
  // Lightweight check that API server is up and env is loaded.
  const hasSupabaseConfig = Boolean(
    process.env.SUPABASE_URL &&
      (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY)
  );

  res.json({
    ok: true,
    service: "backend",
    supabaseConfigured: hasSupabaseConfig
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
    .select("email, full_name, role")
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

  return res.json({
    ok: true,
    message: "Login successful.",
    user: {
      email: profile.email,
      fullName: profile.full_name,
      role: profile.role
    },
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

function normalizeRequestRow(row) {
  return {
    id: row.id,
    referenceNo: row.reference_no,
    title: row.title,
    serviceType: row.service_type,
    preferredDate: row.preferred_date,
    preferredTimeSlot: row.preferred_time_slot,
    status: row.status,
    createdAt: row.created_at || row.submitted_at || null
  };
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

async function resolveFallbackResidentUserId() {
  try {
    const { data: existing, error: existingError } = await supabaseAdmin
      .from("users")
      .select("id")
      .eq("role", "resident")
      .limit(1);

    if (!existingError && existing?.length) {
      return existing[0].id;
    }

    const demoEmail = "resident-demo@serbisyoburgos.local";
    const { data: inserted, error: insertError } = await supabaseAdmin
      .from("users")
      .insert({
        email: demoEmail,
        role: "resident",
        auth_provider: "local",
        is_active: true
      })
      .select("id")
      .single();

    if (!insertError && inserted?.id) return inserted.id;

    const { data: fallbackByEmail } = await supabaseAdmin
      .from("users")
      .select("id")
      .eq("email", demoEmail)
      .maybeSingle();

    return fallbackByEmail?.id || null;
  } catch (_error) {
    return null;
  }
}

app.get("/requests/events", (req, res) => {
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

app.get("/requests", async (_req, res) => {
  const { data, error } = await supabaseAdmin
    .from("service_requests")
    .select("*");

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

  return res.json({
    ok: true,
    request: normalizeRequestRow(data)
  });
});

app.get("/requests/by-reference/:referenceNo", async (req, res) => {
  const referenceNo = String(req.params.referenceNo || "").trim();
  if (!referenceNo) {
    return res.status(400).json({
      ok: false,
      message: "Invalid reference number."
    });
  }

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

  return res.json({
    ok: true,
    request: normalizeRequestRow(data)
  });
});

app.patch("/requests/:id/status", async (req, res) => {
  const id = Number(req.params.id);
  const { status, note } = req.body || {};
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

  const updatePayload = { status: String(status) };
  const { data, error } = await supabaseAdmin
    .from("service_requests")
    .update(updatePayload)
    .eq("id", id)
    .select("*")
    .maybeSingle();

  if (error) {
    return res.status(500).json({
      ok: false,
      message: "Unable to update request status.",
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
  broadcastRequestEvent({
    type: "status-updated",
    request: requestRow,
    note: note ? String(note) : null
  });

  return res.json({
    ok: true,
    request: requestRow
  });
});

app.post("/requests", async (req, res) => {
  const { title, serviceType, preferredDate, preferredTimeSlot } = req.body || {};

  if (!title || !serviceType || !preferredDate || !preferredTimeSlot) {
    return res.status(400).json({
      ok: false,
      message: "title, serviceType, preferredDate, and preferredTimeSlot are required."
    });
  }

  const referenceNo = `REQ-${Math.floor(1000 + Math.random() * 9000)}`;
  const fallbackResidentUserId = await resolveFallbackResidentUserId();
  const insertPayload = {
    reference_no: referenceNo,
    title: String(title).trim(),
    service_type: String(serviceType).trim(),
    preferred_date: preferredDate,
    preferred_time_slot: String(preferredTimeSlot).trim(),
    status: "Pending"
  };
  if (fallbackResidentUserId) {
    insertPayload.resident_user_id = fallbackResidentUserId;
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
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) {
    return res.status(400).json({
      ok: false,
      message: "Invalid request id."
    });
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
