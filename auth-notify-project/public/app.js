const $ = (id) => document.getElementById(id);

let CSRF_TOKEN = null;

async function ensureCsrf() {
  if (CSRF_TOKEN) return CSRF_TOKEN;
  const res = await fetch("/api/csrf", { method: "GET" });
  const data = await res.json();
  CSRF_TOKEN = data.csrfToken;
  return CSRF_TOKEN;
}

$("btnShowRegister").onclick = () => {
  $("registerBox").classList.remove("hidden");
};

$("btnCaptchaDone").onclick = () => {
  const captchaToken = grecaptcha.getResponse();
  if (!captchaToken) {
    $("msg").textContent = "Bạn chưa hoàn thành CAPTCHA.";
    return;
  }
  $("msg").textContent = "";
  $("captchaStep").classList.add("hidden");
  $("formStep").classList.remove("hidden");
};

$("btnRegister").onclick = async () => {
  const captchaToken = grecaptcha.getResponse();

  const payload = {
    fullName: $("fullName").value.trim(),
    email: $("email").value.trim(),
    dob: $("dob").value,
    phone: $("phone").value.trim(),
    password: $("password").value,
    captchaToken
  };

  const csrf = await ensureCsrf();

  const res = await fetch("/api/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf
    },
    body: JSON.stringify(payload)
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    $("msg").textContent = (data.error || "Đăng ký thất bại");

    // Nếu captcha fail/timeout, reset để tick lại
    if (typeof grecaptcha !== "undefined") grecaptcha.reset();
    $("captchaStep").classList.remove("hidden");
    $("formStep").classList.add("hidden");
    return;
  }
  window.location.href = data.redirect || "/blank";
};

$("btnLogin").onclick = async () => {
  const payload = {
    email: $("loginEmail").value.trim(),
    password: $("loginPass").value
  };

  const csrf = await ensureCsrf();

  const res = await fetch("/api/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf
    },
    body: JSON.stringify(payload)
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    alert(data.error || "Đăng nhập thất bại");
    return;
  }
  window.location.href = data.redirect || "/blank";
};
