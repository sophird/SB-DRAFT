(function initAdminAccess(globalScope) {
  const API_BASE_URL = "http://localhost:4000";
  const routes = globalScope.APP_ROUTES || {};
  const fallbackLogin = "../admin-login.html";
  const loginRoute =
    routes.staff?.login ||
    routes.admin?.login ||
    routes.systemAdmin?.login ||
    fallbackLogin;

  const roleHomes = {
staff: routes.staff?.dashboard || "../staff/staff-dashboard.html",
    admin: routes.admin?.dashboard || "../admin/service-mngmt.html",
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

  async function verifyBackendRole(requiredRole, accessToken) {
    const response = await fetch(`${API_BASE_URL}/auth/admin/authorize/${encodeURIComponent(requiredRole)}`, {
      method: "GET",
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!response.ok) throw new Error("Role authorization failed");
  }

  function redirectToLogin() {
    globalScope.location.href = loginRoute;
  }

  function redirectToHome(role) {
    globalScope.location.href = roleHomes[role] || loginRoute;
  }

  async function requireRole(requiredRole) {
    const auth = parseSession();
    if (!auth) {
      redirectToLogin();
      return null;
    }

    const { user, session } = auth;
    if (!user || user.role !== requiredRole) {
      redirectToHome(user?.role);
      return null;
    }

    const accessToken = session?.accessToken;
    if (!accessToken) {
      redirectToLogin();
      return null;
    }

    try {
      await verifyBackendRole(requiredRole, accessToken);
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
