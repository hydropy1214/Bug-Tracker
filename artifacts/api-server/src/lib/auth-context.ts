import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";

function keyFromSecret(): Buffer {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error("SESSION_SECRET is required to store authenticated scan context");
  return createHash("sha256").update(secret).digest();
}

export function encryptAuthHeaders(headers: Record<string, string>): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, keyFromSecret(), iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(headers), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, ciphertext].map((part) => part.toString("base64url")).join(".");
}

export function decryptAuthHeaders(value: string | null): Record<string, string> {
  if (!value) return {};
  const [ivEncoded, tagEncoded, ciphertextEncoded] = value.split(".");
  if (!ivEncoded || !tagEncoded || !ciphertextEncoded) throw new Error("Invalid encrypted auth context");
  const decipher = createDecipheriv(ALGORITHM, keyFromSecret(), Buffer.from(ivEncoded, "base64url"));
  decipher.setAuthTag(Buffer.from(tagEncoded, "base64url"));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(ciphertextEncoded, "base64url")),
    decipher.final(),
  ]).toString("utf8");
  const parsed = JSON.parse(plaintext) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid auth context payload");
  return Object.fromEntries(
    Object.entries(parsed).filter(([key, value]) => key.length > 0 && typeof value === "string"),
  );
}