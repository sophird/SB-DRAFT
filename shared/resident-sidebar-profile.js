(function applyResidentSidebarProfile(global) {
  function initialsFromFullName(fullName) {
    const s = String(fullName || "").trim();
    if (!s) return "";
    const parts = s.split(/\s+/).filter(Boolean);
    if (parts.length >= 2) {
      const a = parts[0][0] || "";
      const b = parts[parts.length - 1][0] || "";
      return (a + b).toUpperCase();
    }
    const one = parts[0];
    if (one.length >= 2) return (one[0] + one[1]).toUpperCase();
    return (one[0] + one[0]).toUpperCase();
  }

  function initialsFromEmail(email) {
    const local = String(email || "").split("@")[0] || "";
    if (local.length >= 2) return local.slice(0, 2).toUpperCase();
    if (local.length === 1) return (local + local).toUpperCase();
    return "?";
  }

  function initialsForUser(user) {
    const full = String(user?.fullName || "").trim();
    if (full) return initialsFromFullName(full);
    return initialsFromEmail(user?.email || "");
  }

  function displayNameForUser(user) {
    if (!user) return "Resident";
    const n = String(user.fullName || "").trim();
    if (n) return n;
    const e = String(user.email || "").trim();
    return e || "Resident";
  }

  function apply() {
    const avatarEl = global.document.getElementById("residentSidebarAvatar");
    const nameEl = global.document.getElementById("residentSidebarName");
    if (!avatarEl && !nameEl) return;

    let user = null;
    try {
      const raw = global.sessionStorage.getItem("residentAuth");
      if (raw) {
        const parsed = JSON.parse(raw);
        user = parsed?.user || null;
      }
    } catch (_e) {
      user = null;
    }

    const display = displayNameForUser(user);
    let initials = initialsForUser(user);
    if (!initials || initials === "?") initials = "R";

    if (nameEl) nameEl.textContent = display;
    if (avatarEl) avatarEl.textContent = initials.slice(0, 2);

    const welcomeEl = global.document.getElementById("residentWelcomeHeading");
    if (welcomeEl && user) {
      welcomeEl.textContent = `Welcome back, ${display}!`;
    }
  }

  if (global.document.readyState === "loading") {
    global.document.addEventListener("DOMContentLoaded", apply);
  } else {
    apply();
  }
})(window);
