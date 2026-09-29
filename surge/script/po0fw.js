/*
 * po0fw.js — po0 防火墙自动加白（自用极简版）
 *
 * 做的事只有一件：对每个 token 发一次
 *   POST <api>/<token>/add[?slot=N]
 * 服务端按来源 /24 幂等加白，客户端不查询、不判断，无脑 POST。
 *
 * 参数（模块 argument）：
 *   api    加白接口 base URL
 *   tokens 别名:token，逗号分隔，别名可省略
 *   slots  网络名@槽位，逗号分隔；网络名为 WiFi SSID，cellular 代表蜂窝，wired 代表有线；未列出的网络不带 slot
 *   quiet  true 只在失败/新占坑位时通知
 *
 * 只用到 Surge 的 $argument / $network / $httpClient / $persistentStore / $notification / $done。
 */

const DEFAULT_API = "https://124.221.69.228/api/firewall";
const IPRE = /\b(\d{1,3}(?:\.\d{1,3}){3})(?:\/(\d{1,2}))?\b/g;

function parseArgs(s) {
  const o = {};
  (s || "").split("&").forEach(kv => {
    const i = kv.indexOf("=");
    if (i > 0) o[kv.slice(0, i)] = decodeURIComponent(kv.slice(i + 1));
  });
  return o;
}

// 当前网络：蜂窝 → cellular；WiFi → SSID；非蜂窝且读不到 SSID → wired
// 注意：Surge 需要定位权限才读得到 SSID，未授权时 WiFi 也会被判成 wired
function currentNet() {
  try {
    if (/^pdp_ip/.test(($network.v4 && $network.v4.primaryInterface) || "")) return { name: "cellular", isCell: true };
    const ssid = $network.wifi && $network.wifi.ssid;
    return { name: ssid || "wired", isCell: false };
  } catch (e) { return { name: "wired", isCell: false }; }
}

function parseSlots(s) {
  const m = new Map();
  (s || "").split(",").map(t => t.trim()).filter(Boolean).forEach(t => {
    const i = t.lastIndexOf("@");
    if (i > 0 && t.slice(i + 1) !== "") m.set(t.slice(0, i), t.slice(i + 1));
  });
  return m;
}

function post(url) {
  return new Promise(resolve => {
    $httpClient.post(
      { url, policy: "DIRECT", insecure: true, timeout: 20, headers: { "User-Agent": "po0fw-surge/1" } },
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
  const api = (args.api || DEFAULT_API).replace(/\/+$/, "");
  const tokens = (args.tokens || "").split(",").map(t => t.trim()).filter(Boolean);
  const quiet = args.quiet !== "false";

  if (!tokens.length) {
    $notification.post("Po0 防火墙", "未配置 tokens", "在模块参数里填入 pgnfw_ 开头的 token");
    return $done({ title: "Po0 防火墙", content: "未配置 tokens" });
  }

  const net = currentNet();
  const slot = parseSlots(args.slots).get(net.name);
  const netLabel = (net.isCell ? "蜂窝" : net.name === "wired" ? "有线" : net.name) + (slot !== undefined ? ` → 槽位 ${slot}` : "");
  const lines = [];

  for (let i = 0; i < tokens.length; i++) {
    const c = tokens[i].indexOf(":");
    const alias = c > 0 ? tokens[i].slice(0, c) : `#${i + 1}`;
    const tok = c > 0 ? tokens[i].slice(c + 1) : tokens[i];
    const url = `${api}/${tok}/add` + (slot !== undefined ? `?slot=${encodeURIComponent(slot)}` : "");
    const key = "po0fw:" + tok.slice(-8);

    const r = await post(url);

    if (r.err || !r.status || r.status >= 400) {
      const msg = r.err ? String(r.err) : `HTTP ${r.status}`;
      $notification.post(`Po0 防火墙 · ${alias}`, `加白失败 · ${msg}`, r.body.slice(0, 120));
      lines.push(`${alias}  ❌ ${msg}`);
      continue;
    }

    const nets = extractNets(r.body);
    const prev = $persistentStore.read(key) || "";
    const prevN = prev ? prev.split(",").length : 0;
    $persistentStore.write(nets.join(","), key);

    if (prevN > 0 && nets.length > prevN) {
      $notification.post(`Po0 防火墙 · ${alias}`, `新占槽位 ${nets.length}/5 · ${netLabel}`, nets.join("\n"));
    } else if (!quiet) {
      $notification.post(`Po0 防火墙 · ${alias}`, `已加白 ${nets.length}/5 · ${netLabel}`, nets.join("\n"));
    }

    lines.push(`${alias}  ✅ ${nets.length ? `已加白 ${nets.length}/5` : "已提交"}`);
    if (nets.length) lines.push("  " + nets.join(" · "));
  }

  const now = new Date();
  const hhmm = `${String(now.getHours()).padStart(2, "0")}:${String(now.getMinutes()).padStart(2, "0")}`;
  lines.push("", `上次运行 ${hhmm}`);

  $done({ title: `Po0 防火墙 · ${netLabel}`, content: lines.join("\n") });
})();
