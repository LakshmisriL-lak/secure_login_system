// Show/hide password + password strength meter (no inline scripts: CSP-friendly)
document.querySelectorAll("[data-toggle]").forEach(function (b) {
  b.addEventListener("click", function () {
    var i = document.getElementById(b.dataset.toggle);
    i.type = i.type === "password" ? "text" : "password";
    b.textContent = i.type === "password" ? "👁️" : "🙈";
  });
});
var pw = document.getElementById("password"), bar = document.getElementById("meter");
if (pw && bar) {
  var colors = ["#ef4444", "#f59e0b", "#eab308", "#22c55e"];
  pw.addEventListener("input", function () {
    var v = pw.value, s = 0;
    if (v.length >= 10) s++;
    if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
    if (/\d/.test(v)) s++;
    if (/[^A-Za-z0-9]/.test(v)) s++;
    bar.style.width = v ? (s * 25 || 10) + "%" : "0";
    bar.style.background = colors[Math.max(s - 1, 0)];
  });
}
