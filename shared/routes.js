(function initRouteMap(globalScope) {
  function normalizePathname(pathname) {
    return String(pathname || "").replace(/\\/g, "/").toLowerCase();
  }

  function computeRootPrefix(pathname) {
    const normalized = normalizePathname(pathname);
    if (
      normalized.includes("/resident/") ||
      normalized.includes("/staff/") ||
      normalized.includes("/admin/") ||
      normalized.includes("/system-admin/")
    ) {
      return "../";
    }
    return "";
  }

  const rootPrefix = computeRootPrefix(globalScope.location?.pathname);
  const ROUTES = {
    common: {
      landing: `${rootPrefix}landing.html`
    },
    entry: {
      residentLogin: `${rootPrefix}resident/resident-login.html`,
      staffLogin: `${rootPrefix}admin-login.html`
    },
    staff: {
      login: `${rootPrefix}admin-login.html`,
      dashboard: `${rootPrefix}staff/staff-dashboard.html`
    },
    admin: {
      login: `${rootPrefix}admin-login.html`,
      dashboard: `${rootPrefix}admin/service-req.html`
    },
    systemAdmin: {
      login: `${rootPrefix}admin-login.html`,
      dashboard: `${rootPrefix}system-admin/sysad-dashboard.html`
    },
    resident: {
      login: "resident-login.html",
      dashboard: "dashboard.html",
      serviceRequests: "service-requests.html",
      appointments: "appointments.html",
      notifications: "notifications.html",
      requestHistory: "request-history.html"
    }
  };

  function logout() {
    sessionStorage.removeItem("adminAuth");
    sessionStorage.removeItem("residentAuth");
    sessionStorage.removeItem("selectedRequest");
    localStorage.removeItem("adminAuth");
    localStorage.removeItem("residentAuth");
    globalScope.location.href = ROUTES.common.landing;
  }

  globalScope.APP_ROUTES = ROUTES;
  globalScope.APP_NAV = { logout };
})(window);
