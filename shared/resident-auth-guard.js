(function initResidentPortalGuard(globalScope) {
  const STORAGE_KEY = "residentAuth";

  function loginHref() {
    return globalScope.APP_ROUTES?.resident?.login || "../resident-login.html";
  }

  function readAccessToken() {
    try {
      const raw = globalScope.sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      const token = parsed?.session?.accessToken;
      return typeof token === "string" && token.length > 0 ? token : null;
    } catch (_err) {
      return null;
    }
  }

  function guard() {
    if (!readAccessToken()) {
      globalScope.location.href = loginHref();
    }
  }

  globalScope.getResidentAccessToken = readAccessToken;
  globalScope.residentApiHeaders = function residentApiHeaders() {
    const token = readAccessToken();
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  globalScope.residentApiFetch = async function residentApiFetch(url, options) {
    const opts = options && typeof options === "object" ? { ...options } : {};
    opts.headers = { ...globalScope.residentApiHeaders(), ...(opts.headers || {}) };
    const response = await globalScope.fetch(url, opts);
    if (response.status === 401) {
      try {
        globalScope.sessionStorage.removeItem(STORAGE_KEY);
        globalScope.sessionStorage.removeItem("residentContext");
      } catch (_e) {
        /* ignore */
      }
      globalScope.location.href = loginHref();
    }
    return response;
  };

  globalScope.residentSseUrl = function residentSseUrl(urlPath) {
    const token = readAccessToken();
    if (!token) return urlPath;
    const joiner = urlPath.includes("?") ? "&" : "?";
    return `${urlPath}${joiner}access_token=${encodeURIComponent(token)}`;
  };

  if (globalScope.document.readyState === "loading") {
    globalScope.document.addEventListener("DOMContentLoaded", guard);
  } else {
    guard();
  }
})(window);
