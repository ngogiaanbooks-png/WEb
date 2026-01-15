const crypto = require("crypto");

function genRefreshToken() {
  return crypto.randomBytes(48).toString("base64url");
}

function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

function genOneTimeToken() {
  return crypto.randomBytes(32).toString("base64url");
}

module.exports = { genRefreshToken, hashToken, genOneTimeToken };
