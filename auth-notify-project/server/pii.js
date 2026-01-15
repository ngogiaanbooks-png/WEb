const crypto = require("crypto");

const key = Buffer.from(process.env.PII_ENC_KEY || "", "base64");

function assertKey() {
  if (key.length !== 32) {
    throw new Error("PII_ENC_KEY must be 32 bytes base64 (AES-256-GCM).");
  }
}

function encryptPII(plain) {
  if (plain === undefined || plain === null || plain === "") return null;
  assertKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${iv.toString("base64")}:${enc.toString("base64")}:${tag.toString("base64")}`;
}

function decryptPII(payload) {
  if (!payload) return null;
  assertKey();
  const [ivB64, encB64, tagB64] = payload.split(":");
  const iv = Buffer.from(ivB64, "base64");
  const enc = Buffer.from(encB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const out = Buffer.concat([decipher.update(enc), decipher.final()]);
  return out.toString("utf8");
}

module.exports = { encryptPII, decryptPII };
