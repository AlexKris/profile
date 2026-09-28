/*
 * po0fw.js — po0 防火墙自动加白（自用极简版）
 *
 * 做的事只有一件：对每个 token 发一次
 *   POST https://124.221.69.228/api/firewall/<token>/add[?slot=N]
 * 服务端按来源 /24 幂等加白，客户端不查询、不判断，无脑 POST。
 *
 * 只用到 Surge 的 $argument / $network / $httpClient / $persistentStore / $notification / $done。
 */

const API = "https://124.221.69.228/api/firewall";
const IPRE = /\b(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?\b/g;

function parseArgs(s) {
  const o = {};
  (s || "").split("&").forEach(kv => {
    const i = kv.indexOf("=");
    if (i > 0) o[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1));
  });
  return o;
}

function onCellular() {
  try { return /^pdp_ip/.test(($network.v4 && $network.v4.primaryInterface) || ""); }
  catch (e) { return false; }
}

function post(url) {
  return new Promise(resolve => {
    $httpClient.post(
      { url, insecure: true, timeout: 20, headers: { "User-Agent": "po0fw-surge/1" } },
      (err, resp, body) => resolve({ err, status: resp && resp.status, body: body || "" })
    );
  });
}

function extractNets(body) {
  const set = new Set();
  let m;
  IPRE.lastIndex = 0;
  while ((m = IPRE.exec(body))) {
    set.add(m[2] ? `${m[1]}/${m[2]}` : m[1].replace(/\.\d+$/, ".0") + "/24");
  }
  return [...set];
}

(async () => {
  const args = parseArgs($argument);
  const tokens = (args.tokens || "").split(",").map(t => t.trim()).filter(Boolean);
  const quiet = args.quiet !== "false";

  if (!tokens.length) {
    $notification.post("po0fw", "未配置 tokens", "在模块参数里填入 pgnfw_ 开头的 token");
    return $done({ title: "po0fw", content: "未配置 tokens" });
  }

  const cell = onCellular();
  const lines = [];

  for (let i = 0; i < tokens.length; i++) {
    const [tok, slot] = tokens[i].split("@");
    const url = `${API}/${tok}/add` + (slot !== undefined && slot !== "" ? `?slot=${encodeURIComponent(slot)}` : "");
    const key = "po0fw:" + tok.slice(-8);
    const tag = `#${i + 1}` + (slot !== undefined && slot !== "" ? ` @${slot}` : "");

    const r = await post(url);

    if (r.err || !r.status || r.status >= 400) {
      const msg = r.err ? String(r.err) : `HTTP ${r.status}`;
      $notification.post(`po0fw ${tag} 加白失败`, msg, r.body.slice(0, 120));
      lines.push(`${tag} ❌ ${msg}`);
      continue;
    }

    const nets = extractNets(r.body);
    const prev = $persistentStore.read(key) || "";
    const prevN = prev ? prev.split(",").length : 0;
    $persistentStore.write(nets.join(","), key);

    if (prevN > 0 && nets.length > prevN) {
      $notification.post(`po0fw ${tag}`, `新占坑位 ${nets.length}/5${cell ? " 📶" : ""}`, nets.join("\n"));
    } else if (!quiet) {
      $notification.post(`po0fw ${tag}`, `已提交 ${nets.length}/5${cell ? " 📶" : ""}`, nets.join("\n"));
    }

    lines.push(`${tag} ✅ ${nets.length ? nets.length + "/5" : "已提交"}${cell ? " 📶" : ""}`);
    nets.forEach(n => lines.push("   " + n));
  }

  $done({ title: `po0fw · ${tokens.length} 机`, content: lines.join("\n") });
})();
