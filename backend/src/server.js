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
  process.env.SUPABASE_URL || "",
  process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY || ""
);
const supabaseAuth = createClient(
  process.env.SUPABASE_URL || "",
  process.env.SUPABASE_ANON_KEY || ""
);

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

  if (!profile || profile.role !== "admin") {
    await supabaseAuth.auth.signOut();
    return res.status(403).json({
      ok: false,
      message: "Access denied. Admin account required."
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
