(function initAdminAccess(globalScope) {
  function resolveApiBaseUrl() {
    var raw =
      typeof globalScope.API_BASE_URL === "string" && globalScope.API_BASE_URL.trim()
        ? globalScope.API_BASE_URL.trim()
        : "https://sb-draft1.onrender.com";
    return raw.replace(/\/$/, "");
  }

  var routes = globalScope.APP_ROUTES || {};
  var fallbackLogin = "../admin-login.html";
  var loginRoute =
    routes.staff?.login ||
    routes.admin?.login ||
    routes.systemAdmin?.login ||
    fallbackLogin;

  var roleHomes = {
    staff: routes.staff?.dashboard || "../staff/staff-dashboard.html",
    admin: routes.admin?.dashboard || "../admin/service-req.html",
    "system-admin": routes.systemAdmin?.dashboard || "../system-admin/sysad-dashboard.html"
  };

  // Track the background refresh timer so we only set it once
  var _refreshTimerId = null;

  function parseSession() {
    try {
      var raw = sessionStorage.getItem("adminAuth");
      if (!raw) return null;
      var parsed = JSON.parse(raw);
      if (!parsed || !parsed.user || !parsed.session) return null;
      return parsed;
    } catch (_e) {
      return null;
    }
  }

  function sleep(ms) {
    return new Promise(function(resolve) { setTimeout(resolve, ms); });
  }

  /**
   * Fetch with retry + exponential backoff.
   * Handles Render free-tier cold starts (network errors / 5xx on wake-up).
   * Never retries 401 or 403 — those are real auth failures.
   */
  async function fetchWithRetry(url, options, retries, baseDelayMs) {
    retries = retries !== undefined ? retries : 3;
    baseDelayMs = baseDelayMs !== undefined ? baseDelayMs : 2000;
    for (var attempt = 0; attempt <= retries; attempt++) {
      try {
        var res = await fetch(url, options);
        if (res.status === 401 || res.status === 403) return res;
        if (!res.ok && attempt < retries) {
          await sleep(baseDelayMs * Math.pow(2, attempt));
          continue;
        }
        return res;
      } catch (_netErr) {
        if (attempt < retries) {
          await sleep(baseDelayMs * Math.pow(2, attempt));
          continue;
        }
        throw _netErr;
      }
    }
  }

  /**
   * Call the backend to exchange a refresh token for a fresh access token.
   * Returns the updated auth object on success, or null on failure.
   */
  async function doRefresh(auth) {
    var refreshToken = auth && auth.session && auth.session.refreshToken;
    if (!refreshToken) return null;
    try {
      var response = await fetchWithRetry(
        resolveApiBaseUrl() + "/auth/admin/refresh",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refreshToken: refreshToken })
        }
      );
      if (!response.ok) return null;
      var result = await response.json();
      if (!result.ok || !result.session || !result.session.accessToken) return null;
      var updated = {
        user: result.user || auth.user,
        session: {
          accessToken: result.session.accessToken,
          refreshToken: result.session.refreshToken || refreshToken,
          expiresAt: result.session.expiresAt
        }
      };
      sessionStorage.setItem("adminAuth", JSON.stringify(updated));
      return updated;
    } catch (_e) {
      return null;
    }
  }

  /**
   * Refresh the token if it expires within the next 5 minutes.
   */
  async function refreshSessionIfNeeded(auth) {
    var expiresAt = auth && auth.session && auth.session.expiresAt;
    if (!expiresAt) return auth; // No expiry info — proceed as-is
    var nowSec = Math.floor(Date.now() / 1000);
    if (expiresAt - nowSec > 5 * 60) return auth; // Still has >5 min — fine
    var refreshed = await doRefresh(auth);
    return refreshed; // null = refresh failed = force login
  }

  /**
   * Schedule a background token refresh so the token never expires while the
   * user is sitting on a page. Fires 2 minutes before expiry, then re-schedules.
   */
  function scheduleBackgroundRefresh(auth) {
    if (_refreshTimerId) {
      clearTimeout(_refreshTimerId);
      _refreshTimerId = null;
    }
    var expiresAt = auth && auth.session && auth.session.expiresAt;
    if (!expiresAt || !auth.session.refreshToken) return;

    var nowSec = Math.floor(Date.now() / 1000);
    var msUntilRefresh = Math.max((expiresAt - nowSec - 120) * 1000, 30000); // at least 30s from now

    _refreshTimerId = setTimeout(async function() {
      var currentAuth = parseSession();
      if (!currentAuth) return; // User logged out
      var refreshed = await doRefresh(currentAuth);
      if (!refreshed) {
        // Refresh failed — token is gone, redirect to login
        globalScope.location.href = loginRoute;
        return;
      }
      // Re-schedule for the new token's expiry
      scheduleBackgroundRefresh(refreshed);
    }, msUntilRefresh);
  }

  async function verifyBackendRole(requiredRole, accessToken) {
    var response = await fetchWithRetry(
      resolveApiBaseUrl() + "/auth/admin/authorize/" + encodeURIComponent(requiredRole),
      {
        method: "GET",
        headers: { Authorization: "Bearer " + accessToken }
      }
    );
    if (!response.ok) throw new Error("Role authorization failed");
  }

  function redirectToLogin() {
    globalScope.location.href = loginRoute;
  }

  function redirectToHome(role) {
    globalScope.location.href = roleHomes[role] || loginRoute;
  }

  async function requireRole(requiredRole) {
    var auth = parseSession();
    if (!auth) { redirectToLogin(); return null; }

    var user = auth.user;
    if (!user || user.role !== requiredRole) { redirectToHome(user && user.role); return null; }

    // Refresh now if the token is already close to expiry
    auth = await refreshSessionIfNeeded(auth);
    if (!auth) { redirectToLogin(); return null; }

    var accessToken = auth.session && auth.session.accessToken;
    if (!accessToken) { redirectToLogin(); return null; }

    try {
      await verifyBackendRole(requiredRole, accessToken);

      // Start background refresh timer so the token stays alive while on this page
      scheduleBackgroundRefresh(auth);

      if (requiredRole !== "system-admin") {
        var env = "production";
        try {
          if (globalScope.SB_MAINTENANCE && globalScope.SB_MAINTENANCE.fetchPortalEnvironment) {
            env = await globalScope.SB_MAINTENANCE.fetchPortalEnvironment();
          } else {
            var statusRes = await fetchWithRetry(resolveApiBaseUrl() + "/public/system-status", {});
            var statusJson = await statusRes.json().catch(function() { return {}; });
            if (statusJson && statusJson.environment === "maintenance") env = "maintenance";
          }
        } catch (_e) { env = "production"; }
        if (env === "maintenance") {
          var target =
            (globalScope.SB_MAINTENANCE && globalScope.SB_MAINTENANCE.maintenancePageHref && globalScope.SB_MAINTENANCE.maintenancePageHref()) ||
            (globalScope.APP_ROUTES && globalScope.APP_ROUTES.common && globalScope.APP_ROUTES.common.maintenance) ||
            "../maintenance.html";
          globalScope.location.href = target;
          return null;
        }
      }
      return auth;
    } catch (_error) {
      redirectToLogin();
      return null;
    }
  }

  globalScope.SB_ADMIN_ACCESS = { loginRoute: loginRoute, roleHomes: roleHomes, requireRole: requireRole };
})(window);