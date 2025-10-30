import { promises as fs } from "fs";
import crypto from "crypto";

const PART_A = process.env.PART_A || "";
if (!PART_A) throw new Error("Missing PART_A (set Actions secret PART_A)");

const PART_B_LENGTH = parseInt(process.env.PART_B_LENGTH || "16", 10);
const FILE_PREFIX   = process.env.FILE_PREFIX   || "paidappsecure_";
const OUTER_ALIAS   = process.env.OUTER_ALIAS   || "latest.json";
const KEYB_PATH     = process.env.KEYB_PATH     || "key_b.txt";
const FALLBACK_OUTER= process.env.FALLBACK_OUTER|| "paidappsecure_encoded_base64.json";
const PREV_KEYB     = "prev_key_b.txt"; // remember key that created current latest.json

const RE_DATED = new RegExp(`^${FILE_PREFIX}(\\d{8})\\.json$`);

function todayYmdUTC(){
  const d=new Date();
  const y=d.getUTCFullYear();
  const m=String(d.getUTCMonth()+1).padStart(2,"0");
  const day=String(d.getUTCDate()).padStart(2,"0");
  return `${y}${m}${day}`;
}
function randPartB(len){
  const alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const buf=crypto.randomBytes(len);
  let s=""; for(let i=0;i<len;i++) s+=alphabet[buf[i]%alphabet.length];
  return s;
}
const b64ToBytes = (b64)=>Buffer.from(b64,"base64");
const bytesToB64 = (buf)=>buf.toString("base64");
function xorBytes(dataBuf,keyStr){
  const keyBuf=Buffer.from(keyStr,"utf8");
  const out=Buffer.allocUnsafe(dataBuf.length);
  for(let i=0;i<dataBuf.length;i++) out[i]=dataBuf[i]^keyBuf[i%keyBuf.length];
  return out;
}
async function readTextIfExists(p){
  try{ return await fs.readFile(p,"utf8"); }catch{ return null; }
}
function looksBase64(s){ return /^[A-Za-z0-9+/=]+$/.test(s); }

// Try to decode a given OUTER (string) with a given partB; return innerBase64 or null
function tryDecodeOuter(outerStr, partB){
  if(!outerStr || !partB) return null;
  const outer = outerStr.trim().replace(/\s+/g,"");
  try{
    const outerBytes = b64ToBytes(outer);
    const innerBase64Bytes = xorBytes(outerBytes, PART_A + partB);
    const innerBase64 = Buffer.from(innerBase64Bytes).toString("latin1");
    if(!looksBase64(innerBase64)) return null;
    // sanity: decode base64 to ensure it’s valid text (JSON later)
    Buffer.from(innerBase64,"base64").toString("utf8");
    return innerBase64;
  }catch{
    return null;
  }
}

async function main(){
  // Load candidates
  let aliasOuter = await readTextIfExists(OUTER_ALIAS);
  let fallbackOuter = await readTextIfExists(FALLBACK_OUTER);
  const currKeyB = (await readTextIfExists(KEYB_PATH))?.trim() || "";
  const prevKeyB = (await readTextIfExists(PREV_KEYB))?.trim() || "";

  if (!aliasOuter && !fallbackOuter){
    throw new Error(`Missing both ${OUTER_ALIAS} and ${FALLBACK_OUTER}. Seed the repo with a working outer blob.`);
  }

  // Try decode in robust order:
  // 1) latest.json + key_b.txt
  // 2) latest.json + prev_key_b.txt
  // 3) fallback + key_b.txt
  // 4) fallback + prev_key_b.txt
  let usedOuterName = null;
  let usedPartB = null;
  let innerBase64 = null;

  if (aliasOuter){
    const try1 = tryDecodeOuter(aliasOuter, currKeyB);
    if (try1){ innerBase64=try1; usedOuterName=OUTER_ALIAS; usedPartB=currKeyB; }
    else {
      const try2 = tryDecodeOuter(aliasOuter, prevKeyB);
      if (try2){ innerBase64=try2; usedOuterName=OUTER_ALIAS; usedPartB=prevKeyB; }
    }
  }
  if (!innerBase64 && fallbackOuter){
    const try3 = tryDecodeOuter(fallbackOuter, currKeyB);
    if (try3){ innerBase64=try3; usedOuterName=FALLBACK_OUTER; usedPartB=currKeyB; }
    else {
      const try4 = tryDecodeOuter(fallbackOuter, prevKeyB);
      if (try4){ innerBase64=try4; usedOuterName=FALLBACK_OUTER; usedPartB=prevKeyB; }
    }
  }

  if (!innerBase64){
    throw new Error("Could not decode any outer blob with available keys. Reseed key_b.txt and the fallback file once.");
  }

  console.log(`Decoded OK from ${usedOuterName} using ${usedPartB === currKeyB ? "current" : "previous"} key_b`);

  // Generate new PART_B and re-encode outer with new key
  const newPartB = randPartB(PART_B_LENGTH);
  const newKey = PART_A + newPartB;
  const newOuterBytes = xorBytes(Buffer.from(innerBase64,"utf8"), newKey);
  const newOuter = bytesToB64(newOuterBytes);

  // Sanity: decode back to ensure correctness before writing anything
  const sanityInner = tryDecodeOuter(newOuter, newPartB);
  if (!sanityInner){ throw new Error("Sanity decode failed after re-encode — aborting write."); }

  // Write outputs (note: write key_b.txt last)
  const ymd = todayYmdUTC();
  const datedName = `${FILE_PREFIX}${ymd}.json`;
  await fs.writeFile(datedName, newOuter, "utf8");
  await fs.writeFile(OUTER_ALIAS, newOuter, "utf8");
  await fs.writeFile(PREV_KEYB, newPartB, "utf8"); // remember the key that created latest.json
  await fs.writeFile(KEYB_PATH, newPartB, "utf8"); // public-facing key used by clients

  console.log(`Wrote ${datedName}, updated ${OUTER_ALIAS}, rotated ${KEYB_PATH}, stored ${PREV_KEYB}`);

  // Prune dated files older than 10 days
  const entries = await fs.readdir(".", { withFileTypes: true });
  const now = Date.now();
  const TEN_DAYS = 10 * 24 * 60 * 60 * 1000;
  for (const ent of entries){
    if (!ent.isFile()) continue;
    const m = ent.name.match(RE_DATED);
    if (!m) continue;
    const y=parseInt(m[1].slice(0,4),10);
    const mo=parseInt(m[1].slice(4,6),10);
    const d=parseInt(m[1].slice(6,8),10);
    const fileDate = Date.UTC(y, mo-1, d);
    if (now - fileDate > TEN_DAYS){
      await fs.unlink(ent.name);
      console.log(`Deleted old file: ${ent.name}`);
    }
  }
}

main().catch(e=>{ console.error(e); process.exit(1); });

