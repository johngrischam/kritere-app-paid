import { promises as fs } from "fs";
import crypto from "crypto";
import path from "path";

const PART_A = process.env.PART_A || "";
if (!PART_A) throw new Error("Missing PART_A (set Actions secret PART_A)");

const PART_B_LENGTH = parseInt(process.env.PART_B_LENGTH || "16", 10);
const FILE_PREFIX = process.env.FILE_PREFIX || "paidappsecure_";
const OUTER_ALIAS = process.env.OUTER_ALIAS || "latest.json";
const KEYB_PATH = process.env.KEYB_PATH || "key_b.txt";
const FALLBACK_OUTER = process.env.FALLBACK_OUTER || "paidappsecure_encoded_base64.json";

const RE_DATED = new RegExp(`^${FILE_PREFIX}(\\d{8})\\.json$`); // e.g. paidappsecure_20251101.json

function todayYmdUTC() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}${m}${day}`;
}

function randPartB(len) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  let s = "";
  const buf = crypto.randomBytes(len);
  for (let i = 0; i < len; i++) s += alphabet[buf[i] % alphabet.length];
  return s;
}

function b64ToBytes(b64) {
  return Buffer.from(b64, "base64");
}
function bytesToB64(buf) {
  return buf.toString("base64");
}

// XOR data with key (key is UTF-8 string)
function xorBytes(dataBuf, keyStr) {
  const keyBuf = Buffer.from(keyStr, "utf8");
  const out = Buffer.allocUnsafe(dataBuf.length);
  for (let i = 0; i < dataBuf.length; i++) {
    out[i] = dataBuf[i] ^ keyBuf[i % keyBuf.length];
  }
  return out;
}

async function readTextIfExists(filePath) {
  try {
    return await fs.readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

async function main() {
  // 1) Load current outer blob and partB (for decoding)
  let outer = await readTextIfExists(OUTER_ALIAS);
  if (!outer) {
    outer = await readTextIfExists(FALLBACK_OUTER);
    if (!outer) {
      throw new Error(
        `Neither ${OUTER_ALIAS} nor ${FALLBACK_OUTER} found. Place your current outer blob in one of these.`
      );
    }
    console.log(`Using fallback outer: ${FALLBACK_OUTER}`);
  } else {
    console.log(`Using alias outer: ${OUTER_ALIAS}`);
  }
  outer = outer.trim().replace(/\s+/g, "");

  const oldPartB = (await readTextIfExists(KEYB_PATH))?.trim() || "";
  if (!oldPartB) {
    throw new Error(
      `Missing ${KEYB_PATH}. Place your current PART_B there for the first run.`
    );
  }

  // 2) Decode to innerBase64 using old key
  const oldKey = PART_A + oldPartB;
const outerBytes = b64ToBytes(outer);
const innerBase64Bytes = xorBytes(outerBytes, oldKey);
const innerBase64 = Buffer.from(innerBase64Bytes).toString("latin1");

  if (!/^[A-Za-z0-9+/=]+$/.test(innerBase64)) {
  throw new Error("Decoded innerBase64 is not valid Base64 — key mismatch or wrong encoding");
}

  // (Optional sanity check) innerBase64 should be valid base64; try decode without throwing
  try {
    Buffer.from(innerBase64, "base64").toString("utf8");
  } catch (e) {
    throw new Error("Failed to decode innerBase64 — check PART_A or key_b.txt");
  }

  // 3) Generate new PART_B and re-encode outer with new key
  const newPartB = randPartB(PART_B_LENGTH);
  const newKey = PART_A + newPartB;

  const newInnerBase64Bytes = Buffer.from(innerBase64, "utf8");
  const newOuterBytes = xorBytes(newInnerBase64Bytes, newKey);
  const newOuter = bytesToB64(newOuterBytes);

  // 4) Write new dated file and alias + overwrite key_b.txt
  const ymd = todayYmdUTC();
  const datedName = `${FILE_PREFIX}${ymd}.json`;

  await fs.writeFile(datedName, newOuter, "utf8");
  await fs.writeFile(OUTER_ALIAS, newOuter, "utf8"); // alias always points to latest
  await fs.writeFile(KEYB_PATH, newPartB, "utf8");

  console.log(`Wrote ${datedName}, updated ${OUTER_ALIAS}, rotated ${KEYB_PATH}`);

  // 5) Prune dated files older than 10 days
  const entries = await fs.readdir(".", { withFileTypes: true });
  const now = Date.now();
  const TEN_DAYS = 10 * 24 * 60 * 60 * 1000;

  for (const ent of entries) {
    if (!ent.isFile()) continue;
    const m = ent.name.match(RE_DATED);
    if (!m) continue;
    const ymdStr = m[1]; // YYYYMMDD
    const y = parseInt(ymdStr.slice(0, 4), 10);
    const mo = parseInt(ymdStr.slice(4, 6), 10);
    const d = parseInt(ymdStr.slice(6, 8), 10);
    const fileDate = Date.UTC(y, mo - 1, d); // midnight UTC
    if (now - fileDate > TEN_DAYS) {
      await fs.unlink(ent.name);
      console.log(`Deleted old file: ${ent.name}`);
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
