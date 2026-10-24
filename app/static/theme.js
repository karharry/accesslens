// Applies the saved theme before first paint. "system" = no data-theme attribute (follows the OS).
(function () {
  var t = null;
  try { t = localStorage.getItem("al-theme"); } catch (e) {}
  if (t === "light" || t === "dark") document.documentElement.setAttribute("data-theme", t);
})();
