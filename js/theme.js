/* Runs in <head> before paint so the page never flashes the wrong theme. */
(function () {
  var choice = "system";
  try { choice = localStorage.getItem("theme") || "system"; } catch (e) {}
  var dark = choice === "dark" || (choice === "system" && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.setAttribute("data-theme", dark ? "dark" : "light");
  document.documentElement.setAttribute("data-theme-choice", choice);
})();
