(function initAdminAccess(globalScope) {
  function resolveApiBaseUrl() {
    const raw =
      typeof globalScope.API_BASE_URL === "string" && globalScope.API_BASE_URL.trim()
        ? globalScope.API_BASE_URL.trim()
        : "https://sb-draft1.onrender.com";
    return raw.replace(/\/$/, "");
  }
  const routes = globalScope.APP_ROUTES || {};
  const fallbackLogin = "../admin-login.html";
  const loginRoute =
    routes.staff?.login ||
    routes.admin?.login ||
    routes.systemAdmin?.login ||
    fallbackLogin;

  const roleHomes = {
    staff: routes.staff?.dashboard || "../staff/staff-dashboard.html",
    admin: routes.admin?.dashboard || "../admin/service-req.html",
    "system-admin": routes.systemAdmin?.dashboard || "../system-admin/sysad-dashboard.html"
  };

  function parseSession() {
    try {
      const raw = sessionStorage.getItem("adminAuth");
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || !parsed.user || !parsed.session) return null;
      return parsed;
    } catch (_error) {
      return null;
    }
  }

  async function refreshSessionIfNeeded(auth) {
    const expiresAt = auth?.session?.expiresAt;
    const refreshToken = auth?.session?.refreshToken;
    if (!expiresAt || !refreshToken) return auth;

    // Refresh if token expires within the next 5 minutes
    const nowSec = Math.floor(Date.now() / 1000);
    const bufferSec = 5 * 60;
    if (expiresAt - nowSec > bufferSec) return auth; // Still valid, no refresh needed

    try {
      const response = await fetch(`${resolveApiBaseUrl()}/auth/admin/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken })
      });
      if (!response.ok) return null; // Refresh failed — force re-login
      const result = await response.json();
      if (!result.ok || !result.session?.accessToken) return null;

      // Update sessionStorage with fresh tokens
      const updated = {
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
      return null; // Network error — force re-login
    }
  }

  async function verifyBackendRole(requiredRole, accessToken) {
    const response = await fetch(
      `${resolveApiBaseUrl()}/auth/admin/authorize/${encodeURIComponent(requiredRole)}`,
      {
        method: "GET",
        headers: { Authorization: `Bearer ${accessToken}` }
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
    let auth = parseSession();
    if (!auth) {
      redirectToLogin();
      return null;
    }

    const { user } = auth;
    if (!user || user.role !== requiredRole) {
      redirectToHome(user?.role);
      return null;
    }

    // Refresh token if it's close to expiry
    auth = await refreshSessionIfNeeded(auth);
    if (!auth) {
      redirectToLogin();
      return null;
    }

    const accessToken = auth.session?.accessToken;
    if (!accessToken) {
      redirectToLogin();
      return null;
    }

    try {
      await verifyBackendRole(requiredRole, accessToken);
      if (requiredRole !== "system-admin") {
        let env = "production";
        try {
          if (globalScope.SB_MAINTENANCE?.fetchPortalEnvironment) {
            env = await globalScope.SB_MAINTENANCE.fetchPortalEnvironment();
          } else {
            const response = await fetch(`${resolveApiBaseUrl()}/public/system-status`);
            const json = await response.json().catch(() => ({}));
            if (json?.environment === "maintenance") env = "maintenance";
          }
        } catch (_e) {
          env = "production";
        }
        if (env === "maintenance") {
          const target =
            globalScope.SB_MAINTENANCE?.maintenancePageHref?.() ||
            globalScope.APP_ROUTES?.common?.maintenance ||
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

  globalScope.SB_ADMIN_ACCESS = {
    loginRoute,
    roleHomes,
    requireRole
  };
})(window);