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

  const normalizedPath = normalizePathname(globalScope.location?.pathname);
  const rootPrefix = computeRootPrefix(globalScope.location?.pathname);
  const inResidentFolder = normalizedPath.includes("/resident/");
  const residentFolderPrefix = inResidentFolder ? "" : "resident/";

  const ROUTES = {
    common: {
      landing: `${rootPrefix}landing.html`,
      maintenance: `${rootPrefix}maintenance.html`
    },
    entry: {
      residentLogin: `${rootPrefix}resident-login.html`,
      staffLogin: `${rootPrefix}admin-login.html`
    },
    staff: {
      login: `${rootPrefix}admin-login.html`,
      dashboard: `${rootPrefix}staff/staff-dashboard.html`
    },
admin: {
      login: `${rootPrefix}admin-login.html`,
      dashboard: `${rootPrefix}admin/service-mngmt.html`
    },
    systemAdmin: {
      login: `${rootPrefix}admin-login.html`,
      dashboard: `${rootPrefix}system-admin/sys-config.html`
    },
    resident: {
      login: `${rootPrefix}resident-login.html`,
      dashboard: `${residentFolderPrefix}dashboard.html`,
      serviceRequests: `${residentFolderPrefix}service-requests.html`,
      appointments: `${residentFolderPrefix}appointments.html`,
      notifications: `${residentFolderPrefix}notifications.html`,
      requestHistory: `${residentFolderPrefix}request-history.html`
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
