/* Na Locker – small client-side helpers (no inline scripts, CSP friendly). */
document.addEventListener("DOMContentLoaded", function () {
  // Password visibility toggles
  document.querySelectorAll(".toggle-password").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var input = document.getElementById(btn.dataset.target);
      var show = input.type === "password";
      input.type = show ? "text" : "password";
      btn.textContent = show ? "Hide" : "Show";
      btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
    });
  });

  // Confirm before delete
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      if (!window.confirm(form.dataset.confirm)) { e.preventDefault(); }
    });
  });

  // Registration validation
  var reg = document.getElementById("register-form");
  if (reg) {
    var showError = function (name, msg) {
      var el = reg.querySelector('[data-error-for="' + name + '"]');
      var input = reg.elements[name];
      el.textContent = msg; el.hidden = !msg;
      input.classList.toggle("invalid", !!msg);
      return !msg;
    };
    reg.addEventListener("submit", function (e) {
      var f = reg.elements, ok = true;
      var name = f.name.value.trim(), email = f.email.value.trim();
      var pw = f.password.value, cpw = f.confirm_password.value;
      ok = showError("name", name.length >= 2 && name.length <= 60 ? "" : "Please enter your name (2-60 characters).") && ok;
      ok = showError("email", /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? "" : "Please enter a valid email address.") && ok;
      var pwMsg = "";
      if (pw.length < 8) pwMsg = "Password must be at least 8 characters long.";
      else if (!/[A-Za-z]/.test(pw) || !/[0-9]/.test(pw)) pwMsg = "Password must contain at least one letter and one number.";
      ok = showError("password", pwMsg) && ok;
      ok = showError("confirm_password", pw === cpw ? "" : "Passwords do not match.") && ok;
      if (!ok) { e.preventDefault(); reg.querySelector(".invalid").focus(); }
    });
  }

  // Upload: drag & drop, file name display, size check
  var dz = document.getElementById("dropzone");
  if (dz) {
    var input = document.getElementById("document");
    var title = document.getElementById("dropzone-title");
    var err = document.getElementById("upload-error");
    var original = title.textContent;
    var check = function () {
      var file = input.files[0];
      err.hidden = true;
      if (!file) { title.textContent = original; return true; }
      title.textContent = file.name;
      if (file.size > Number(input.dataset.maxBytes)) {
        err.textContent = "That file is larger than the 10 MB limit.";
        err.hidden = false; return false;
      }
      return true;
    };
    input.addEventListener("change", check);
    ["dragenter", "dragover"].forEach(function (ev) {
      dz.addEventListener(ev, function () { dz.classList.add("dragover"); });
    });
    ["dragleave", "drop"].forEach(function (ev) {
      dz.addEventListener(ev, function () { dz.classList.remove("dragover"); });
    });
    document.getElementById("upload-form").addEventListener("submit", function (e) {
      if (!check()) e.preventDefault();
    });
  }
});
