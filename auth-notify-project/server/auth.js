const jwt = require("jsonwebtoken");

function signAccessToken(user) {
  const ttlMin = Number(process.env.ACCESS_TOKEN_TTL_MIN || 15);
  return jwt.sign(
    { uid: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: `${ttlMin}m` }
  );
}

function setAccessCookie(res, accessJwt) {
  res.cookie("access_token", accessJwt, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: Number(process.env.ACCESS_TOKEN_TTL_MIN || 15) * 60 * 1000
  });
}

function setRefreshCookie(res, refreshToken) {
  res.cookie("refresh_token", refreshToken, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    // giới hạn refresh token chỉ gửi cho endpoint refresh
    path: "/api/refresh",
    maxAge: Number(process.env.REFRESH_TOKEN_TTL_DAYS || 30) * 24 * 60 * 60 * 1000
  });
}

function clearAuthCookies(res) {
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/api/refresh" });
}

module.exports = { signAccessToken, setAccessCookie, setRefreshCookie, clearAuthCookies };
