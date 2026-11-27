// Language and theme toggles. The page is fully readable without this script (Korean, system theme).
(function () {
  var root = document.documentElement;

  function save(key, value) {
    try { localStorage.setItem(key, value); } catch (e) { /* storage unavailable: setting lasts for this page view */ }
  }

  document.getElementById("lang-toggle").addEventListener("click", function () {
    var next = root.getAttribute("data-lang") === "en" ? "ko" : "en";
    root.setAttribute("data-lang", next);
    root.lang = next;
    save("nz-lang", next);
  });

  document.getElementById("theme-toggle").addEventListener("click", function () {
    var current = root.getAttribute("data-theme");
    if (!current) {
      current = window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }
    var next = current === "dark" ? "light" : "dark";
    root.setAttribute("data-theme", next);
    save("nz-theme", next);
  });
})();
