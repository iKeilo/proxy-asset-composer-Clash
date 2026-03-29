const sampleRawInput = [
  "ss://YWVzLTI1Ni1nY206cGFzc0BleGFtcGxlLmNvbTo4NDQz#香港专线-01",
  "ss://YWVzLTI1Ni1nY206cGFzc0B1cy5leGFtcGxlLmNvbTo4NDQz#美国下载-01",
  "vmess://eyJhZGQiOiJ0dy5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJwcyI6IklYLVRXIElTUC0wMSIsImlkIjoiMTIzNCIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInRscyI6InRscyJ9",
  "trojan://password@uk.example.com:443#英国节点-01",
  "hysteria2://pass@jp.example.com:443?sni=jp.example.com#JP-HY2[IIJ]-01",
  "vless://uuid-1234@hk-reality.example.com:443?encryption=none&security=reality&sni=hk.example.com&pbk=publickey&fp=chrome&type=tcp#香港Reality-01"
].join("\n");

const sampleRulesInput = [
  "sniffer:",
  "  enable: true",
  "  sniffing: [tls, http, quic]",
  "  force-dns-mapping: true",
  "  parse-pure-ip: true",
  "  override-destination: true",
  "rule-providers:",
  "  TikTok:",
  "    type: http",
  "    behavior: classical",
  "    path: ./ruleset/TikTok.yaml",
  "    url: \"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml\"",
  "    interval: 86400",
  "rules:",
  "  - RULE-SET,TikTok,国际抖音",
  "  - DOMAIN-SUFFIX,netflix.com,Netflix",
  "  - MATCH,节点选择"
].join("\n");

const templates = {
  basic: {
    strategies: [
      { name: "香港专线", type: "url-test", members: [{ kind: "node", value: "香港专线-01" }] },
      { name: "美国节点", type: "url-test", members: [{ kind: "asset", value: "美国资产库" }] },
      { name: "节点选择", type: "select", members: [{ kind: "strategy", value: "香港专线" }, { kind: "strategy", value: "美国节点" }, { kind: "constant", value: "DIRECT" }] }
    ]
  }
};

const allowedConstants = ["DIRECT", "REJECT"];
const allowedProxyGroupTypes = ["select", "url-test", "fallback", "load-balance", "relay"];
const ruleTailOptions = new Set(["no-resolve", "src", "dst"]);
const defaultClashBaseRaw = [
  "port: 7890",
  "socks-port: 7891",
  "allow-lan: true",
  "unified-delay: true",
  "mode: Rule",
  "log-level: info",
  "external-controller: :9090",
  "dns:",
  "  enable: true",
  "  nameserver:",
  "    - 119.29.29.29",
  "    - 223.5.5.5",
  "  fallback:",
  "    - 8.8.8.8",
  "    - 8.8.4.4",
  "    - tls://1.0.0.1:853",
  "    - tls://dns.google:853"
].join("\n");
const defaultSnifferRaw = [
  "enable: true",
  "sniffing: [tls, http, quic]",
  "force-dns-mapping: true",
  "parse-pure-ip: true",
  "override-destination: true"
].join("\n");
const defaultProvidersRaw = [
  "TikTok:",
  "  type: http",
  "  behavior: classical",
  "  path: ./ruleset/TikTok.yaml",
  "  url: \"https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml\"",
  "  interval: 86400"
].join("\n");
let persistTimer = null;
let outputRenderTimer = null;
const yamlParseCache = new Map();
const yamlParseError = Symbol("yamlParseError");
const ruleEditorDrafts = {
  groups: new Map(),
  rules: new Map()
};
const flagRegionMap = [
  ["🇺🇲", "美国资产库"],
  ["🇺🇸", "美国资产库"],
  ["🇬🇧", "英国资产库"],
  ["🇭🇰", "香港资产库"],
  ["🇹🇼", "台湾资产库"],
  ["🇯🇵", "日本资产库"],
  ["🇸🇬", "新加坡资产库"],
  ["🇰🇷", "韩国资产库"],
  ["🇩🇪", "德国资产库"],
  ["🇫🇷", "法国资产库"]
];

const state = {
  nodes: [],
  assets: [],
  strategies: [],
  exportVersion: 0,
  importedConfigPath: "",
  lastSavedConfigPath: "",
  clashBaseRaw: defaultClashBaseRaw,
  rulesConfig: {
    snifferRaw: defaultSnifferRaw,
    providersRaw: defaultProvidersRaw,
    rules: []
  },
  nodeModalAssetId: null
};

const els = {
  appVersionLabel: document.querySelector("#appVersionLabel"),
  rawInput: document.querySelector("#rawInput"),
  clashConfigInput: document.querySelector("#clashConfigInput"),
  templateFileInput: document.querySelector("#templateFileInput"),
  clashConfigFileInput: document.querySelector("#clashConfigFileInput"),
  chooseClashConfigBtn: document.querySelector("#chooseClashConfigBtn"),
  normalizeBtn: document.querySelector("#normalizeBtn"),
  importTemplateBtn: document.querySelector("#importTemplateBtn"),
  exportTemplateBtn: document.querySelector("#exportTemplateBtn"),
  importClashConfigBtn: document.querySelector("#importClashConfigBtn"),
  openConfigBtn: document.querySelector("#openConfigBtn"),
  closeConfigBtn: document.querySelector("#closeConfigBtn"),
  configPage: document.querySelector("#configPage"),
  loadSampleBtn: document.querySelector("#loadSampleBtn"),
  seedAssetsBtn: document.querySelector("#seedAssetsBtn"),
  addAssetBtn: document.querySelector("#addAssetBtn"),
  addStrategyBtn: document.querySelector("#addStrategyBtn"),
  loadTemplateBtn: document.querySelector("#loadTemplateBtn"),
  addProviderBtn: document.querySelector("#addProviderBtn"),
  addRuleGroupBtn: document.querySelector("#addRuleGroupBtn"),
  addRuleBtn: document.querySelector("#addRuleBtn"),
  exportBtn: document.querySelector("#exportBtn"),
  targetFormat: document.querySelector("#targetFormat"),
  configFileInput: document.querySelector("#configFileInput"),
  importConfigBtn: document.querySelector("#importConfigBtn"),
  exportConfigBtn: document.querySelector("#exportConfigBtn"),
  configExportName: document.querySelector("#configExportName"),
  openSnifferEditorBtn: document.querySelector("#openSnifferEditorBtn"),
  closeSnifferEditorBtn: document.querySelector("#closeSnifferEditorBtn"),
  snifferPage: document.querySelector("#snifferPage"),
  openProvidersEditorBtn: document.querySelector("#openProvidersEditorBtn"),
  closeProvidersEditorBtn: document.querySelector("#closeProvidersEditorBtn"),
  providersPage: document.querySelector("#providersPage"),
  closeNodeModalBtn: document.querySelector("#closeNodeModalBtn"),
  nodeModal: document.querySelector("#nodeModal"),
  nodeImportTextarea: document.querySelector("#nodeImportTextarea"),
  submitNodeImportBtn: document.querySelector("#submitNodeImportBtn"),
  openKeywordGroupBtn: document.querySelector("#openKeywordGroupBtn"),
  closeKeywordGroupBtn: document.querySelector("#closeKeywordGroupBtn"),
  keywordGroupModal: document.querySelector("#keywordGroupModal"),
  keywordGroupName: document.querySelector("#keywordGroupName"),
  keywordGroupPattern: document.querySelector("#keywordGroupPattern"),
  keywordRegexToggle: document.querySelector("#keywordRegexToggle"),
  submitKeywordGroupBtn: document.querySelector("#submitKeywordGroupBtn"),
  assetGrid: document.querySelector("#assetGrid"),
  strategyEditor: document.querySelector("#strategyEditor"),
  snifferEditor: document.querySelector("#snifferEditor"),
  providersEditor: document.querySelector("#providersEditor"),
  snifferSummary: document.querySelector("#snifferSummary"),
  providersSummary: document.querySelector("#providersSummary"),
  rulesEditor: document.querySelector("#rulesEditor"),
  outputPreview: document.querySelector("#outputPreview"),
  assetCount: document.querySelector("#assetCount"),
  nodeCount: document.querySelector("#nodeCount"),
  strategyCount: document.querySelector("#strategyCount"),
  ruleCount: document.querySelector("#ruleCount"),
  resolveInfo: document.querySelector("#resolveInfo"),
  validationPanel: document.querySelector("#validationPanel"),
  saveWorkspaceBtn: document.querySelector("#saveWorkspaceBtn"),
  assetTemplate: document.querySelector("#assetTemplate"),
  assetNodeTemplate: document.querySelector("#assetNodeTemplate"),
  strategyTemplate: document.querySelector("#strategyTemplate"),
  strategyMemberTemplate: document.querySelector("#strategyMemberTemplate"),
  providerTemplate: document.querySelector("#providerTemplate"),
  ruleTemplate: document.querySelector("#ruleTemplate")
};

function cloneYamlValue(value) {
  if (value == null || typeof value !== "object") return value;
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value));
}

function rememberYamlParse(key, value) {
  if (yamlParseCache.size >= 24) {
    const oldestKey = yamlParseCache.keys().next().value;
    if (oldestKey !== undefined) yamlParseCache.delete(oldestKey);
  }
  yamlParseCache.set(key, value);
}

function safeYamlLoad(text) {
  const raw = String(text ?? "");
  if (!raw.trim()) return null;
  if (yamlParseCache.has(raw)) {
    const cached = yamlParseCache.get(raw);
    return cached === yamlParseError ? null : cloneYamlValue(cached);
  }
  try {
    const parsed = window.jsyaml.load(raw);
    rememberYamlParse(raw, parsed);
    return cloneYamlValue(parsed);
  } catch {
    rememberYamlParse(raw, yamlParseError);
    return null;
  }
}

function normalizeYamlDumpText(text) {
  const lines = String(text || "").split(/\r?\n/);
  const normalized = [];
  for (let i = 0; i < lines.length; i += 1) {
    const current = lines[i].replace(/^(\s*external-controller:\s*)"([^"]+)"\s*$/, "$1$2");
    const sniffingMatch = current.match(/^(\s*)sniffing:\s*$/);
    if (sniffingMatch) {
      const baseIndent = sniffingMatch[1];
      const items = [];
      let cursor = i + 1;
      while (cursor < lines.length) {
        const nextLine = lines[cursor];
        if (!nextLine.startsWith(`${baseIndent}  - `)) break;
        items.push(nextLine.replace(/^\s*-\s*/, "").trim());
        cursor += 1;
      }
      if (items.length) {
        normalized.push(`${baseIndent}sniffing: [${items.join(", ")}]`);
        i = cursor - 1;
        continue;
      }
    }
    normalized.push(current);
  }
  return normalized.join("\n").trim();
}

function dumpYaml(value) {
  if (value == null) return "";
  return normalizeYamlDumpText(window.jsyaml.dump(value, {
    lineWidth: -1,
    noRefs: true,
    quotingType: "\""
  }).trim());
}

function dumpYamlFlow(value) {
  if (value == null) return "";
  return window.jsyaml.dump(value, {
    lineWidth: -1,
    noRefs: true,
    quotingType: "\"",
    flowLevel: 0
  }).trim();
}

function dumpYamlBlock(value) {
  const dumped = dumpYaml(value);
  return dumped ? dumped.split(/\r?\n/) : [];
}

function isNumericString(value) {
  return /^-?\d+(\.\d+)?$/.test(value);
}

function yamlInlineScalar(value, key = "") {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (Array.isArray(value)) return `[${value.map((item) => yamlInlineScalar(item)).join(", ")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value).map(([k, v]) => `${k}: ${yamlInlineScalar(v, k)}`).join(", ")}}`;

  const text = String(value);
  if (key === "short-id") return `"${text.replace(/"/g, '\\"')}"`;
  if (/^(true|false|null)$/i.test(text)) return `"${text}"`;
  if (isNumericString(text)) return `"${text}"`;
  if (/[\s,:{}[\]#]|^$/.test(text)) return `"${text.replace(/"/g, '\\"')}"`;
  return text;
}

function formatInlineProxy(proxy) {
  return `{${Object.entries(proxy).map(([key, value]) => `${key}: ${yamlInlineScalar(value, key)}`).join(", ")}}`;
}

function normalizeYamlScalar(value) {
  if (Array.isArray(value)) return value.map(normalizeYamlScalar);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, normalizeYamlScalar(item)]));
  }
  if (typeof value !== "string") return value;
  if (/^(true|false)$/i.test(value)) return value.toLowerCase() === "true";
  if (/^null$/i.test(value)) return null;
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
  return value;
}

function buildProxyExportObject(node) {
  const original = normalizeYamlScalar(node.proxyFields || {});
  const proxy = { ...original };

  if (node.name !== undefined && node.name !== null && String(node.name) !== String(original.name ?? "")) {
    proxy.name = node.name;
  } else if (!("name" in proxy)) {
    proxy.name = node.name;
  }

  if (node.host !== undefined && node.host !== null && String(node.host) !== String(original.server ?? "")) {
    proxy.server = node.host;
  } else if (!("server" in proxy)) {
    proxy.server = node.host || "test.test";
  }

  if (node.port !== undefined && node.port !== null && String(node.port) !== String(original.port ?? "")) {
    proxy.port = Number(node.port);
  } else if (!("port" in proxy)) {
    proxy.port = Number(node.port || "443");
  }

  if (node.protocol && String(node.protocol) !== String(original.type ?? "")) {
    proxy.type = node.protocol;
  } else if (!("type" in proxy)) {
    proxy.type = node.protocol || "ss";
  }

  return proxy;
}

function uid(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
}

function strategyWithDefaults(strategy) {
  return {
    collapsed: true,
    providerRefs: [],
    members: [],
    ...strategy
  };
}

function ensureStrategyStateDefaults() {
  state.strategies = state.strategies.map((strategy) => strategyWithDefaults(strategy));
}

function moveStrategyToIndex(strategyId, targetIndex) {
  const fromIndex = state.strategies.findIndex((item) => item.id === strategyId);
  if (fromIndex === -1) return;
  const boundedTargetIndex = Math.max(0, Math.min(targetIndex, state.strategies.length - 1));
  if (fromIndex === boundedTargetIndex) return;
  const [moved] = state.strategies.splice(fromIndex, 1);
  state.strategies.splice(boundedTargetIndex, 0, moved);
  render();
}

function emptyNode(protocol = "ss") {
  return { id: uid("node"), name: "", host: "", port: "", protocol, note: "", raw: "" };
}

function emptyRule() {
  return { id: uid("rule"), type: "MATCH", value: "", target: "节点选择" };
}

function ruleWithDefaults(rule = {}) {
  const target = rule.target || "节点选择";
  return {
    id: rule.id || uid("rule"),
    type: rule.type || "MATCH",
    value: rule.value || "",
    target,
    tails: Array.isArray(rule.tails) ? rule.tails.filter(Boolean) : [],
    group: rule.group || target
  };
}

function ensureRuleStateDefaults() {
  state.rulesConfig.rules = (Array.isArray(state.rulesConfig.rules) ? state.rulesConfig.rules : []).map((rule) => ruleWithDefaults(rule));
}

function emptyRule(overrides = {}) {
  return ruleWithDefaults({ type: "MATCH", value: "", target: "节点选择", ...overrides });
}

function getRuleGroupName(rule) {
  return rule.group || rule.target || "未分组";
}

function buildRuleGroups() {
  ensureRuleStateDefaults();
  const groups = [];
  const groupMap = new Map();
  state.rulesConfig.rules.forEach((rule) => {
    const groupName = getRuleGroupName(rule);
    if (!groupMap.has(groupName)) {
      const group = {
        name: groupName,
        rules: [],
        targets: new Set(),
        isCustom: false
      };
      groupMap.set(groupName, group);
      groups.push(group);
    }
    const group = groupMap.get(groupName);
    group.rules.push(rule);
    if (rule.target) group.targets.add(rule.target);
    if (groupName !== (rule.target || "")) group.isCustom = true;
  });
  return groups;
}

function createRuleGroupName(baseName = "新分组") {
  const existing = new Set(buildRuleGroups().map((group) => group.name));
  if (!existing.has(baseName)) return baseName;
  let index = 1;
  while (existing.has(`${baseName}${index}`)) index += 1;
  return `${baseName}${index}`;
}

function normalizeRuleType(type) {
  const known = [
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN",
    "RULE-SET",
    "GEOSITE",
    "GEOIP",
    "IP-CIDR",
    "IP-CIDR6",
    "PROCESS-NAME",
    "DST-PORT",
    "AND",
    "MATCH"
  ];
  return known.includes(type) ? type : "MATCH";
}

function splitRuleParts(rawValue) {
  const sourceText = Array.isArray(rawValue)
    ? rawValue.map((item) => String(item)).join(",")
    : String(rawValue || "");
  const normalizedText = sourceText.replace(/\s+#.*$/, "").trim();
  const parts = normalizedText.split(",").map((item) => item.trim());
  const type = normalizeRuleType(parts[0] || "MATCH");
  const body = parts.slice(1);
  const tails = [];
  while (body.length > 1 && ruleTailOptions.has(String(body[body.length - 1] || "").toLowerCase())) {
    tails.unshift(body.pop());
  }
  const target = String(body.pop() || "节点选择").trim();
  const value = body.join(",").trim();
  return { type, value, target, tails };
}

function normalizeProxyGroupType(type) {
  return allowedProxyGroupTypes.includes(type) ? type : "select";
}

function toggleOverlay(el, open) {
  el.classList.toggle("hidden", !open);
}

function closeNodeModal() {
  state.nodeModalAssetId = null;
  els.nodeImportTextarea.value = "";
  toggleOverlay(els.nodeModal, false);
}

function closeKeywordGroupModal() {
  els.keywordGroupName.value = "";
  els.keywordGroupPattern.value = "";
  els.keywordRegexToggle.checked = false;
  toggleOverlay(els.keywordGroupModal, false);
}

function openNodeModal(assetId) {
  state.nodeModalAssetId = assetId;
  els.nodeImportTextarea.value = "";
  toggleOverlay(els.nodeModal, true);
}

function decodeSafe(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function regionFlag(name) {
  const pairs = [
    ["香港", "🇭🇰"],
    ["HK", "🇭🇰"],
    ["美国", "🇺🇸"],
    ["US", "🇺🇸"],
    ["英国", "🇬🇧"],
    ["UK", "🇬🇧"],
    ["台湾", "🇹🇼"],
    ["TW", "🇹🇼"],
    ["日本", "🇯🇵"],
    ["JP", "🇯🇵"],
    ["新加坡", "🇸🇬"],
    ["SG", "🇸🇬"],
    ["韩国", "🇰🇷"],
    ["KR", "🇰🇷"],
    ["德国", "🇩🇪"],
    ["DE", "🇩🇪"],
    ["法国", "🇫🇷"],
    ["FR", "🇫🇷"]
  ];
  const hit = pairs.find(([token]) => name.includes(token));
  return hit ? hit[1] : "";
}

function withRegionFlag(name) {
  if (!name) return name;
  if (/^[\uD83C-\uDBFF\uDC00-\uDFFF]/.test(name)) return name;
  const flag = regionFlag(name);
  return flag ? `${flag} ${name}` : name;
}

function parseUrlParts(line) {
  const [scheme] = line.split("://");
  const raw = line.slice(`${scheme}://`.length);
  const [beforeHash, hash = ""] = raw.split("#");
  const [beforeQuery, queryString = ""] = beforeHash.split("?");
  return {
    scheme,
    beforeQuery,
    params: new URLSearchParams(queryString),
    name: withRegionFlag(decodeSafe((hash || guessName(line, scheme)).trim()))
  };
}

function parseVlessNode(line) {
  const { beforeQuery, params, name } = parseUrlParts(line);
  const [userInfo = "", hostPort = ""] = beforeQuery.split("@");
  const [host = "example.com", port = "443"] = hostPort.split(":");
  const security = params.get("security");
  const sni = params.get("sni") || params.get("servername") || "";
  const fp = params.get("fp") || params.get("client-fingerprint") || "";
  const pbk = params.get("pbk") || "";
  const sid = params.get("sid") || "";
  const node = {
    id: uid("node"),
    name,
    host,
    port,
    protocol: "vless",
    note: buildTags(name, "vless", line).join(" / "),
    region: guessRegion(name),
    raw: line,
    proxyFields: {
      name,
      server: host,
      port: Number(port),
      type: "vless",
      uuid: userInfo,
      tls: true,
      tfo: false,
      "skip-cert-verify": false,
      network: params.get("type") || "tcp"
    }
  };

  if (params.get("flow")) node.proxyFields.flow = params.get("flow");
  if (sni) node.proxyFields.servername = sni;
  if (fp) node.proxyFields["client-fingerprint"] = fp;
  if (security === "reality") {
    node.proxyFields["reality-opts"] = {
      "public-key": pbk,
      "short-id": sid
    };
  } else if (security === "tls") {
    node.proxyFields.tls = true;
  }

  return node;
}

function parseTrojanNode(line) {
  const { beforeQuery, params, name } = parseUrlParts(line);
  const [password = "", hostPort = ""] = beforeQuery.split("@");
  const [host = "example.com", port = "443"] = hostPort.split(":");
  return {
    id: uid("node"),
    name,
    host,
    port,
    protocol: "trojan",
    note: buildTags(name, "trojan", line).join(" / "),
    region: guessRegion(name),
    raw: line,
    proxyFields: {
      name,
      server: host,
      port: Number(port),
      type: "trojan",
      password,
      sni: params.get("sni") || undefined,
      "skip-cert-verify": false
    }
  };
}

function parseHysteria2Node(line) {
  const { beforeQuery, params, name } = parseUrlParts(line);
  const [password = "", hostPort = ""] = beforeQuery.split("@");
  const [host = "example.com", port = "443"] = hostPort.split(":");
  return {
    id: uid("node"),
    name,
    host,
    port,
    protocol: "hysteria2",
    note: buildTags(name, "hysteria2", line).join(" / "),
    region: guessRegion(name),
    raw: line,
    proxyFields: {
      name,
      server: host,
      port: Number(port),
      type: "hysteria2",
      password,
      auth: password,
      sni: params.get("sni") || undefined,
      "skip-cert-verify": false
    }
  };
}

function guessName(line, scheme) {
  if (scheme === "vmess") {
    try {
      const payload = JSON.parse(atob(line.replace("vmess://", "")));
      return payload.ps || "VMess-Node";
    } catch {
      return "VMess-Node";
    }
  }
  return `${scheme.toUpperCase()}-Node`;
}

function guessHost(line) {
  const match = line.match(/@([^:/?#]+)(?::\d+)?/);
  return match ? match[1] : "example.com";
}

function guessPort(line) {
  const match = line.match(/:(\d+)(?:\?|#|$)/);
  return match ? match[1] : "443";
}

function guessRegion(name) {
  const flagHit = flagRegionMap.find(([flag]) => name.startsWith(flag));
  if (flagHit) return flagHit[1];
  const pairs = [
    ["香港", "香港资产库"],
    ["HK", "香港资产库"],
    ["美国", "美国资产库"],
    ["US", "美国资产库"],
    ["英国", "英国资产库"],
    ["UK", "英国资产库"],
    ["台湾", "台湾资产库"],
    ["TW", "台湾资产库"],
    ["日本", "日本资产库"],
    ["JP", "日本资产库"],
    ["SG", "新加坡资产库"],
    ["KR", "韩国资产库"],
    ["DE", "德国资产库"],
    ["FR", "法国资产库"]
  ];
  return pairs.find(([token]) => name.includes(token))?.[1] || "未分类资产库";
}

function buildTags(name, scheme, line) {
  const tags = [scheme.toUpperCase()];
  if (/reality/i.test(line)) tags.push("Reality");
  if (name.includes("下载")) tags.push("Download");
  if (name.includes("专线")) tags.push("Premium");
  return tags;
}

function parseNodeLine(line) {
  const [scheme] = line.split("://");
  if (scheme === "vless") return parseVlessNode(line);
  if (scheme === "trojan") return parseTrojanNode(line);
  if (scheme === "hysteria2") return parseHysteria2Node(line);
  const name = decodeSafe((line.split("#")[1] || guessName(line, scheme)).trim());
  return {
    id: uid("node"),
    name: withRegionFlag(name),
    host: guessHost(line),
    port: guessPort(line),
    protocol: scheme,
    note: buildTags(name, scheme, line).join(" / "),
    region: guessRegion(name),
    raw: line,
    proxyFields: {
      name: withRegionFlag(name),
      server: guessHost(line),
      port: Number(guessPort(line)),
      type: scheme
    }
  };
}

function normalizeRawInput(raw) {
  return raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean).map(parseNodeLine);
}

function parseInlineArray(raw) {
  const clean = raw.trim().replace(/^\[/, "").replace(/\]$/, "");
  return clean ? clean.split(",").map((item) => item.trim().replace(/^["']|["']$/g, "")) : [];
}

function seedAssetsFromNodes() {
  const grouped = new Map();
  state.nodes.forEach((node) => {
    if (!grouped.has(node.region)) grouped.set(node.region, { id: uid("asset"), name: node.region, kind: "region", nodes: [] });
    grouped.get(node.region).nodes.push({ ...node });
  });
  state.assets = Array.from(grouped.values());
}

function appendNodesToAssets(nodes) {
  const assetMap = new Map(state.assets.map((asset) => [asset.name, asset]));
  const existingNames = new Set(
    state.assets.flatMap((asset) => asset.nodes.map((node) => String(node.name)))
  );
  nodes.forEach((node) => {
    let nextName = String(node.name || "未命名节点");
    let suffix = 1;
    while (existingNames.has(nextName)) {
      nextName = `${node.name}${suffix}`;
      suffix += 1;
    }
    if (nextName !== node.name) {
      node.name = nextName;
      if (node.proxyFields) node.proxyFields.name = nextName;
    }

    const assetName = node.region || guessRegion(node.name || "");
    if (!assetMap.has(assetName)) {
      const asset = { id: uid("asset"), name: assetName, kind: "region", nodes: [] };
      state.assets.push(asset);
      assetMap.set(assetName, asset);
    }
    const asset = assetMap.get(assetName);
    asset.nodes.push(node);
    existingNames.add(String(node.name));
  });
  state.nodes = state.assets.flatMap((asset) => asset.nodes);
}

function ensureUniqueNodeNamesAcrossAssets() {
  const seen = new Set();
  state.assets.forEach((asset) => {
    asset.nodes.forEach((node) => {
      const baseName = String(node.name || "未命名节点");
      let nextName = baseName;
      let suffix = 1;
      while (seen.has(nextName)) {
        nextName = `${baseName}${suffix}`;
        suffix += 1;
      }
      if (nextName !== node.name) {
        node.name = nextName;
        if (node.proxyFields) node.proxyFields.name = nextName;
      }
      seen.add(nextName);
    });
  });
  state.nodes = state.assets.flatMap((asset) => asset.nodes);
}

function applyTemplate(template) {
  const existing = new Set(state.strategies.map((item) => item.name));
  template.strategies.forEach((strategy) => {
    if (existing.has(strategy.name)) return;
    state.strategies.push(strategyWithDefaults({
      id: uid("strategy"),
      name: strategy.name,
      type: strategy.type,
      members: strategy.members.map((member) => ({ ...member }))
    }));
  });
}

function ensureStrategyExists(name) {
  if (ruleTailOptions.has(String(name || "").toLowerCase())) return;
  if (!name || allowedConstants.includes(name)) return;
  if (state.strategies.some((item) => item.name === name)) return;
  state.strategies.push(strategyWithDefaults({
    id: uid("strategy"),
    name,
    type: "select",
    members: [{ kind: "constant", value: "DIRECT" }]
  }));
}

function importRulesConfig(text) {
  const lines = text.split(/\r?\n/);
  const rules = [];
  let section = "";
  const snifferLines = [];
  const providerLines = [];

  lines.forEach((rawLine) => {
    const line = rawLine.trim();
    if (!line) return;
    if (line === "sniffer:") {
      section = "sniffer";
      return;
    }
    if (line === "rule-providers:") {
      section = "providers";
      return;
    }
    if (line === "rules:") {
      section = "rules";
      return;
    }

    if (section === "sniffer") {
      snifferLines.push(rawLine.replace(/^\s{2}/, ""));
      return;
    }

    if (section === "providers") {
      providerLines.push(rawLine.replace(/^\s{2}/, ""));
      return;
    }

    if (section === "rules" && line.startsWith("- ")) {
      const parts = line.slice(2).split(",");
      const type = normalizeRuleType(parts[0]?.trim() || "MATCH");
      const target = parts[parts.length - 1]?.trim() || "节点选择";
      const value = parts.length > 2 ? parts.slice(1, -1).join(",").trim() : "";
      rules.push(ruleWithDefaults({ id: uid("rule"), type, value, target }));
      ensureStrategyExists(target);
    }
  });

  state.rulesConfig = {
    snifferRaw: snifferLines.join("\n"),
    providersRaw: providerLines.join("\n"),
    rules
  };
}

function collectSection(lines, startIndex, stopPatterns) {
  const out = [];
  for (let i = startIndex; i < lines.length; i += 1) {
    const line = lines[i];
    if (i !== startIndex && stopPatterns.some((pattern) => pattern.test(line.trim()))) break;
    out.push(line);
  }
  return out;
}

function parseInlineProxyMap(line) {
  const body = line.trim().replace(/^- /, "").replace(/^\{/, "").replace(/\}$/, "");
  const result = {};
  let token = "";
  let depth = 0;
  const parts = [];

  for (const ch of body) {
    if (ch === "{" || ch === "[") depth += 1;
    if (ch === "}" || ch === "]") depth -= 1;
    if (ch === "," && depth === 0) {
      parts.push(token);
      token = "";
      continue;
    }
    token += ch;
  }
  if (token.trim()) parts.push(token);

  parts.forEach((part) => {
    const idx = part.indexOf(":");
    if (idx === -1) return;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim().replace(/^["']|["']$/g, "");
    result[key] = value;
  });
  return result;
}

function cloneProxyFields(proxy) {
  const fields = {};
  Object.entries(proxy || {}).forEach(([key, value]) => {
    if (key === "raw") return;
    fields[key] = value;
  });
  return fields;
}

function buildAssetsFromImportedProxies(proxies) {
  const assetMap = new Map();
  proxies.forEach((proxy) => {
    const region = guessRegion(proxy.name || "");
    if (!assetMap.has(region)) {
      assetMap.set(region, { id: uid("asset"), name: region, kind: "region", nodes: [] });
    }
    assetMap.get(region).nodes.push({
      id: uid("node"),
      name: proxy.name || "未命名节点",
      host: proxy.server || "test.test",
      port: proxy.port || "443",
      protocol: proxy.type || "ss",
      note: proxy.raw || "",
      raw: proxy.raw || "",
      proxyFields: cloneProxyFields(proxy)
    });
  });
  return Array.from(assetMap.values());
}

function importProxyGroups(lines) {
  const drafts = [];
  let current = null;
  let listField = "";
  let groupIndent = 0;
  let listIndent = 0;

  lines.forEach((rawLine) => {
    const indent = rawLine.match(/^\s*/)?.[0].length || 0;
    const line = rawLine.trim();
    if (!line) return;
    if (/^- name:/.test(line)) {
      if (current) drafts.push(current);
      current = {
        id: uid("strategy"),
        name: line.split(":").slice(1).join(":").trim().replace(/^["']|["']$/g, ""),
        type: "select",
        proxyNames: [],
        providerRefs: []
      };
      groupIndent = indent;
      listField = "";
      listIndent = 0;
      return;
    }
    if (!current) return;

    if (indent <= groupIndent) {
      listField = "";
      listIndent = 0;
      return;
    }

    if (indent === groupIndent + 2 && line.startsWith("type:")) {
      current.type = normalizeProxyGroupType(line.split(":").slice(1).join(":").trim());
      return;
    }

    if (indent === groupIndent + 2 && (line === "proxies:" || line === "use:")) {
      listField = line.slice(0, -1);
      listIndent = indent;
      return;
    }

    if (listField === "proxies" && indent >= listIndent && line.startsWith("- ")) {
      current.proxyNames.push(line.slice(2).trim().replace(/^["']|["']$/g, ""));
      return;
    }

    if (listField === "use" && indent >= listIndent && line.startsWith("- ")) {
      current.providerRefs.push(line.slice(2).trim().replace(/^["']|["']$/g, ""));
    }
  });

  if (current) drafts.push(current);
  if (!drafts.length) return;

  const strategyNames = new Set(drafts.map((item) => item.name));
  const nodeNames = new Set(state.assets.flatMap((asset) => asset.nodes.map((node) => node.name)));

  state.strategies = drafts.map((draft) => strategyWithDefaults({
    id: draft.id,
    name: draft.name,
    type: normalizeProxyGroupType(draft.type),
    providerRefs: Array.isArray(draft.providerRefs) ? draft.providerRefs : [],
    members: draft.proxyNames.map((value) => ({
      kind: allowedConstants.includes(value)
        ? "constant"
        : strategyNames.has(value)
          ? "strategy"
          : nodeNames.has(value)
            ? "node"
            : "node",
      value
    }))
  }));
}

function importProxyGroupsFromConfig(groups) {
  if (!Array.isArray(groups) || !groups.length) return;

  const drafts = groups.map((group) => ({
    id: uid("strategy"),
    name: group.name || "未命名策略组",
    type: normalizeProxyGroupType(group.type || "select"),
    providerRefs: Array.isArray(group.use) ? group.use.map((item) => String(item)) : [],
    proxyNames: Array.isArray(group.proxies) ? group.proxies.map((item) => String(item)) : []
  }));

  const strategyNames = new Set(drafts.map((item) => item.name));
  const nodeNames = new Set(state.assets.flatMap((asset) => asset.nodes.map((node) => node.name)));

  state.strategies = drafts.map((draft) => strategyWithDefaults({
    id: draft.id,
    name: draft.name,
    type: draft.type,
    providerRefs: draft.providerRefs,
    members: draft.proxyNames.map((value) => ({
      kind: allowedConstants.includes(value)
        ? "constant"
        : strategyNames.has(value)
          ? "strategy"
          : nodeNames.has(value)
            ? "node"
            : "node",
      value
    }))
  }));
}

function importClashConfig(text) {
  const parsedConfig = safeYamlLoad(text);
  if (parsedConfig && typeof parsedConfig === "object" && !Array.isArray(parsedConfig)) {
    const baseConfig = { ...parsedConfig };
    delete baseConfig.sniffer;
    delete baseConfig["rule-providers"];
    delete baseConfig.proxies;
    delete baseConfig["proxy-groups"];
    delete baseConfig.rules;

    state.assets = [];
    state.nodes = [];
    state.strategies = [];
    state.rulesConfig.rules = [];
    state.clashBaseRaw = dumpYaml(baseConfig) || state.clashBaseRaw;
    state.rulesConfig.snifferRaw = dumpYaml(parsedConfig.sniffer) || "";
    state.rulesConfig.providersRaw = dumpYaml(parsedConfig["rule-providers"]) || "";

    if (Array.isArray(parsedConfig.proxies) && parsedConfig.proxies.length) {
      const proxies = parsedConfig.proxies.map((proxy) => ({
        ...proxy,
        raw: ""
      }));
      state.assets = buildAssetsFromImportedProxies(proxies);
      state.nodes = state.assets.flatMap((asset) => asset.nodes);
      ensureUniqueNodeNamesAcrossAssets();
    }

    importProxyGroupsFromConfig(parsedConfig["proxy-groups"]);

    if (Array.isArray(parsedConfig.rules)) {
      state.rulesConfig.rules = parsedConfig.rules.map((rule) => {
        const parts = Array.isArray(rule) ? rule : String(rule).split(",");
        const type = normalizeRuleType(String(parts[0] || "MATCH").trim());
        const target = String(parts[parts.length - 1] || "节点选择").trim();
        const value = parts.length > 2 ? parts.slice(1, -1).join(",").trim() : "";
        ensureStrategyExists(target);
        return ruleWithDefaults({ id: uid("rule"), type, value, target });
      });
    }

    return;
  }

  const lines = text.split(/\r?\n/);
  const snifferIndex = lines.findIndex((line) => /^sniffer:\s*$/.test(line.trim()));
  const providersIndex = lines.findIndex((line) => /^rule-providers:\s*$/.test(line.trim()));
  const proxiesIndex = lines.findIndex((line) => /^proxies:\s*$/.test(line.trim()));
  const proxyGroupsIndex = lines.findIndex((line) => /^proxy-groups:\s*$/.test(line.trim()));
  const rulesIndex = lines.findIndex((line) => /^rules:\s*$/.test(line.trim()));

  const cutIndexes = [snifferIndex, providersIndex, proxiesIndex, proxyGroupsIndex, rulesIndex].filter((index) => index !== -1);
  const firstCut = cutIndexes.length ? Math.min(...cutIndexes) : lines.length;

  state.assets = [];
  state.nodes = [];
  state.strategies = [];
  state.rulesConfig.rules = [];
  state.clashBaseRaw = lines.slice(0, firstCut).join("\n").trim() || state.clashBaseRaw;

  if (snifferIndex !== -1) {
    state.rulesConfig.snifferRaw = collectSection(
      lines,
      snifferIndex + 1,
      [/^rule-providers:\s*$/, /^proxy-groups:\s*$/, /^rules:\s*$/]
    ).map((line) => line.replace(/^\s{2}/, "")).join("\n").trim();
  }

  if (providersIndex !== -1) {
    state.rulesConfig.providersRaw = collectSection(
      lines,
      providersIndex + 1,
      [/^proxies:\s*$/, /^proxy-groups:\s*$/, /^rules:\s*$/]
    ).map((line) => line.replace(/^\s{2}/, "")).join("\n").trim();
  }

  if (proxiesIndex !== -1) {
    const proxyLines = collectSection(
      lines,
      proxiesIndex + 1,
      [/^proxy-groups:\s*$/, /^rules:\s*$/]
    ).filter((line) => line.trim().startsWith("- {"));
    const proxies = proxyLines.map((line) => {
      const parsed = parseInlineProxyMap(line.trim());
      return {
        ...parsed,
        raw: line.trim().replace(/^- /, "")
      };
    });
    if (proxies.length) {
      state.assets = buildAssetsFromImportedProxies(proxies);
      state.nodes = state.assets.flatMap((asset) => asset.nodes);
    }
  }

  if (rulesIndex !== -1) {
    const rules = [];
    const knownStrategyNames = new Set(state.strategies.map((item) => item.name));
    lines.slice(rulesIndex + 1).forEach((rawLine) => {
      const line = rawLine.trim();
      if (!line.startsWith("- ")) return;
      const parts = line.slice(2).split(",");
      const type = normalizeRuleType(parts[0]?.trim() || "MATCH");
      const target = parts[parts.length - 1]?.trim() || "节点选择";
      const value = parts.length > 2 ? parts.slice(1, -1).join(",").trim() : "";
      rules.push(ruleWithDefaults({ id: uid("rule"), type, value, target }));
      if (!knownStrategyNames.has(target)) ensureStrategyExists(target);
    });
    state.rulesConfig.rules = rules;
  }

  if (proxyGroupsIndex !== -1) {
    importProxyGroups(lines.slice(proxyGroupsIndex + 1, rulesIndex === -1 ? lines.length : rulesIndex));
  }
}

function seedDemoData() {
  state.nodes = normalizeRawInput(sampleRawInput);
  seedAssetsFromNodes();
  importRulesConfig(sampleRulesInput);
  applyTemplate(templates.basic);
}

function getDefaultConfigText() {
  return [
    defaultClashBaseRaw,
    "",
    "sniffer:",
    ...indentBlock(state.rulesConfig.snifferRaw),
    "",
    "rule-providers:",
    ...indentBlock(state.rulesConfig.providersRaw),
    "",
    "proxy-groups:",
    "  - name: 鑺傜偣閫夋嫨",
    "    type: select",
    "    proxies:",
    "      - DIRECT",
    "",
    "rules:",
    "  - MATCH,鑺傜偣閫夋嫨"
  ].join("\n");
}

function snapshotState() {
  return {
    importedConfigPath: state.importedConfigPath,
    lastSavedConfigPath: state.lastSavedConfigPath,
    exportVersion: state.exportVersion,
    rawInput: els.rawInput.value,
    clashConfigInput: els.clashConfigInput.value,
    targetFormat: els.targetFormat.value,
    configExportName: els.configExportName.value,
    state: {
      assets: state.assets,
      strategies: state.strategies,
      clashBaseRaw: state.clashBaseRaw,
      rulesConfig: state.rulesConfig
    }
  };
}

function schedulePersist() {
  if (!window.desktopAPI?.saveSession) return;
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    window.desktopAPI.saveSession(snapshotState()).catch(() => {});
  }, 250);
}

function hydrateFromSnapshot(snapshot) {
  if (!snapshot || !snapshot.state) return false;
  state.importedConfigPath = snapshot.importedConfigPath || "";
  state.lastSavedConfigPath = snapshot.lastSavedConfigPath || "";
  state.exportVersion = Number.isInteger(snapshot.exportVersion) ? snapshot.exportVersion : 0;
  state.assets = Array.isArray(snapshot.state.assets) ? snapshot.state.assets : [];
  state.strategies = Array.isArray(snapshot.state.strategies) ? snapshot.state.strategies.map(strategyWithDefaults) : [];
  state.clashBaseRaw = normalizeYamlDumpText(snapshot.state.clashBaseRaw || defaultClashBaseRaw);
  state.rulesConfig = {
    snifferRaw: normalizeYamlDumpText(snapshot.state.rulesConfig?.snifferRaw || defaultSnifferRaw),
    providersRaw: snapshot.state.rulesConfig?.providersRaw || defaultProvidersRaw,
    rules: Array.isArray(snapshot.state.rulesConfig?.rules) ? snapshot.state.rulesConfig.rules.map((rule) => ruleWithDefaults(rule)) : []
  };
  state.nodes = state.assets.flatMap((asset) => Array.isArray(asset.nodes) ? asset.nodes : []);
  els.rawInput.value = snapshot.rawInput || "";
  els.clashConfigInput.value = snapshot.clashConfigInput || getDefaultConfigText();
  els.targetFormat.value = snapshot.targetFormat || "clash";
  els.configExportName.value = snapshot.configExportName || "";
  return true;
}

function getPreferredSavePath(fileName) {
  const sourcePath = state.importedConfigPath || state.lastSavedConfigPath;
  if (!sourcePath) return fileName;
  const normalizedName = fileName || sourcePath.split(/[\\/]/).pop() || "config.yaml";
  return sourcePath.replace(/[^\\/]+$/, normalizedName);
}

function submitNodeImport() {
  const raw = els.nodeImportTextarea.value.trim();
  const asset = state.assets.find((item) => item.id === state.nodeModalAssetId);
  if (!raw || !asset) return;
  const parsedNodes = normalizeRawInput(raw);
  parsedNodes.forEach((parsed) => {
    const exists = asset.nodes.some((item) => item.name === parsed.name && String(item.host) === String(parsed.host) && String(item.port) === String(parsed.port));
    if (!exists) asset.nodes.push(parsed);
  });
  closeNodeModal();
  ensureUniqueNodeNamesAcrossAssets();
  render();
}

function applyKeywordGrouping() {
  const assetName = els.keywordGroupName.value.trim();
  const pattern = els.keywordGroupPattern.value.trim();
  if (!assetName || !pattern) return;

  const matcher = els.keywordRegexToggle.checked
    ? new RegExp(pattern, "i")
    : { test: (value) => value.toLowerCase().includes(pattern.toLowerCase()) };

  const matchedNodes = state.assets.flatMap((asset) => asset.nodes).filter((node) => matcher.test(node.name));
  if (!matchedNodes.length) return;

  const deduped = Array.from(new Map(matchedNodes.map((node) => [node.name, { ...node }])).values());
  const existing = state.assets.find((asset) => asset.name === assetName);
  if (existing) {
    existing.nodes = deduped;
  } else {
    state.assets.push({ id: uid("asset"), name: assetName, kind: "custom", nodes: deduped });
  }
  closeKeywordGroupModal();
  ensureUniqueNodeNamesAcrossAssets();
  render();
}

function exportTemplateDb() {
  const ruleTargets = new Set(
    state.rulesConfig.rules
      .map((rule) => rule.target)
      .filter((target) => target && !allowedConstants.includes(target))
  );
  const payload = {
    rulesConfig: {
      snifferRaw: state.rulesConfig.snifferRaw,
      providersRaw: state.rulesConfig.providersRaw,
      rules: state.rulesConfig.rules
    },
    strategies: state.strategies.map((strategy) => ({
      name: strategy.name,
      type: strategy.type,
      members: [{ kind: "constant", value: "DIRECT" }]
    })).filter((strategy) => ruleTargets.has(strategy.name))
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "proxy-template.db";
  link.click();
  URL.revokeObjectURL(url);
}

function nextVersionName() {
  const name = `ver0.0.${state.exportVersion}`;
  state.exportVersion += 1;
  return name;
}

async function exportCurrentConfig() {
  commitRuleEditorDrafts();
  const result = buildOutputModel();
  const content = formatClash(result);
  const rawName = els.configExportName.value.trim();
  const baseName = rawName || nextVersionName();
  const finalName = /\.(yaml|yml|txt)$/i.test(baseName) ? baseName : `${baseName}.yaml`;
  if (window.desktopAPI?.saveConfigFile) {
    const targetPath = getPreferredSavePath(finalName);
    const saved = await window.desktopAPI.saveConfigFile({ defaultPath: targetPath, content });
    if (!saved?.filePath) return;
    state.lastSavedConfigPath = saved.filePath;
    if (!state.importedConfigPath) state.importedConfigPath = saved.filePath;
    schedulePersist();
    return;
  }
  const blob = new Blob([content], { type: "text/yaml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = finalName;
  link.click();
  URL.revokeObjectURL(url);
}

function importTemplateDb(text) {
  try {
    const data = JSON.parse(text);
    if (data.rulesConfig) {
      state.rulesConfig.snifferRaw = data.rulesConfig.snifferRaw || state.rulesConfig.snifferRaw;
      state.rulesConfig.providersRaw = data.rulesConfig.providersRaw || state.rulesConfig.providersRaw;
      state.rulesConfig.rules = Array.isArray(data.rulesConfig.rules) ? data.rulesConfig.rules.map((rule) => ruleWithDefaults(rule)) : [];
    }
    if (Array.isArray(data.strategies)) {
      state.strategies = data.strategies.map((strategy) => strategyWithDefaults({
        id: uid("strategy"),
        name: strategy.name,
        type: strategy.type || "select",
        members: Array.isArray(strategy.members) && strategy.members.length ? strategy.members : [{ kind: "constant", value: "DIRECT" }]
      }));
    }
  } catch {
    return;
  }
}

function bindEvents() {
  els.openConfigBtn.addEventListener("click", () => toggleOverlay(els.configPage, true));
  els.closeConfigBtn.addEventListener("click", () => toggleOverlay(els.configPage, false));
  els.configPage.querySelector(".config-overlay").addEventListener("click", () => toggleOverlay(els.configPage, false));
  els.importConfigBtn.addEventListener("click", async () => {
    if (window.desktopAPI?.openConfigFile) {
      const picked = await window.desktopAPI.openConfigFile();
      if (!picked) return;
      state.importedConfigPath = picked.filePath;
      els.clashConfigInput.value = picked.text;
      importClashConfig(picked.text);
      render();
      return;
    }
    els.configFileInput.click();
  });
  els.configFileInput.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    els.clashConfigInput.value = text;
    importClashConfig(text);
    render();
  });
  els.exportConfigBtn.addEventListener("click", exportCurrentConfig);
  els.openSnifferEditorBtn.addEventListener("click", () => toggleOverlay(els.snifferPage, true));
  els.closeSnifferEditorBtn.addEventListener("click", () => toggleOverlay(els.snifferPage, false));
  els.snifferPage.querySelector(".config-overlay").addEventListener("click", () => toggleOverlay(els.snifferPage, false));
  els.openProvidersEditorBtn.addEventListener("click", () => toggleOverlay(els.providersPage, true));
  els.closeProvidersEditorBtn.addEventListener("click", () => toggleOverlay(els.providersPage, false));
  els.providersPage.querySelector(".config-overlay").addEventListener("click", () => toggleOverlay(els.providersPage, false));
  els.closeNodeModalBtn.addEventListener("click", closeNodeModal);
  els.nodeModal.querySelector(".config-overlay").addEventListener("click", closeNodeModal);
  els.openKeywordGroupBtn.addEventListener("click", () => toggleOverlay(els.keywordGroupModal, true));
  els.closeKeywordGroupBtn.addEventListener("click", closeKeywordGroupModal);
  els.keywordGroupModal.querySelector(".config-overlay").addEventListener("click", closeKeywordGroupModal);
  if (els.loadSampleBtn) {
    els.loadSampleBtn.addEventListener("click", () => { els.rawInput.value = sampleRawInput; });
  }
  els.importTemplateBtn.addEventListener("click", () => els.templateFileInput.click());
  els.templateFileInput.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    importTemplateDb(text);
    render();
  });
  els.chooseClashConfigBtn.addEventListener("click", async () => {
    if (window.desktopAPI?.openConfigFile) {
      const picked = await window.desktopAPI.openConfigFile();
      if (!picked) return;
      state.importedConfigPath = picked.filePath;
      els.clashConfigInput.value = picked.text;
      importClashConfig(picked.text);
      render();
      return;
    }
    els.clashConfigFileInput.click();
  });
  els.clashConfigFileInput.addEventListener("change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    els.clashConfigInput.value = text;
    importClashConfig(text);
    render();
  });
  els.importClashConfigBtn.addEventListener("click", () => { importClashConfig(els.clashConfigInput.value); render(); });
  els.normalizeBtn.addEventListener("click", () => {
    const parsedNodes = normalizeRawInput(els.rawInput.value);
    appendNodesToAssets(parsedNodes);
    ensureUniqueNodeNamesAcrossAssets();
    render();
  });
  els.exportTemplateBtn.addEventListener("click", exportTemplateDb);
  els.seedAssetsBtn.addEventListener("click", () => { if (!state.nodes.length) state.nodes = normalizeRawInput(els.rawInput.value); seedAssetsFromNodes(); render(); });
  els.addAssetBtn.addEventListener("click", () => { state.assets.push({ id: uid("asset"), name: "新资产库", kind: "custom", nodes: [] }); render(); });
  els.addStrategyBtn.addEventListener("click", () => {
    state.strategies.unshift(strategyWithDefaults({ id: uid("strategy"), name: "新策略层", type: "select", members: [{ kind: "constant", value: "DIRECT" }] }));
    render();
  });
  if (els.loadTemplateBtn) {
    els.loadTemplateBtn.addEventListener("click", () => { applyTemplate(templates.basic); render(); });
  }
  els.addProviderBtn.addEventListener("click", () => {
    state.rulesConfig.providersRaw = `${state.rulesConfig.providersRaw}\n\nNewProvider:\n  type: http\n  behavior: classical\n  path: ./ruleset/NewProvider.yaml\n  url: ""\n  interval: 86400`.trim();
    renderRulePanels();
    renderRules();
    renderOutput();
  });
  els.addRuleBtn.addEventListener("click", () => { state.rulesConfig.rules.push(emptyRule()); ensureStrategyExists("节点选择"); renderRules(); renderOutput(); });
  els.addRuleGroupBtn.addEventListener("click", () => {
    const groupName = createRuleGroupName();
    state.rulesConfig.rules.push(emptyRule({ group: groupName }));
    ensureStrategyExists("节点选择");
    renderRules();
    renderOutput();
  });
  els.submitNodeImportBtn.addEventListener("click", submitNodeImport);
  els.submitKeywordGroupBtn.addEventListener("click", applyKeywordGrouping);
  els.exportBtn.addEventListener("click", renderOutput);
  els.targetFormat.addEventListener("change", renderOutput);
  els.rawInput.addEventListener("input", schedulePersist);
  els.clashConfigInput.addEventListener("input", schedulePersist);
  els.configExportName.addEventListener("input", schedulePersist);
}

function renderAssets() {
  els.assetGrid.innerHTML = "";
  state.assets.forEach((asset) => {
    const card = els.assetTemplate.content.firstElementChild.cloneNode(true);
    card.querySelector(".asset-name").value = asset.name;
    card.querySelector(".asset-kind").value = asset.kind;
    card.querySelector(".asset-summary").textContent = `${asset.nodes.length} 个节点，可修改名称、地址、端口和备注，协议只读`;
    card.querySelector(".asset-name").addEventListener("input", (event) => {
      asset.name = event.target.value.trim() || "未命名资产库";
      renderStats();
      schedulePersist();
    });
    card.querySelector(".asset-kind").addEventListener("change", (event) => { asset.kind = event.target.value; renderOutput(); });
    card.querySelector(".asset-add-node").addEventListener("click", () => openNodeModal(asset.id));
    card.querySelector(".asset-delete").addEventListener("click", () => { state.assets = state.assets.filter((item) => item.id !== asset.id); render(); });

    const nodeList = card.querySelector(".asset-node-list");
    asset.nodes.forEach((node) => {
      if (!node.proxyFields) {
        node.proxyFields = {
          name: node.name,
          server: node.host,
          port: String(node.port || "443"),
          type: node.protocol || "ss"
        };
      }
      const row = els.assetNodeTemplate.content.firstElementChild.cloneNode(true);
      row.querySelector(".node-name").value = node.name;
      row.querySelector(".node-host").value = node.host;
      row.querySelector(".node-port").value = node.port;
      row.querySelector(".node-protocol").value = node.protocol.toUpperCase();
      row.querySelector(".node-note").value = node.note;
      row.querySelector(".node-name").addEventListener("input", (event) => { node.name = event.target.value; node.proxyFields.name = node.name; renderOutput(); });
      row.querySelector(".node-host").addEventListener("input", (event) => { node.host = event.target.value; node.proxyFields.server = node.host; renderOutput(); });
      row.querySelector(".node-port").addEventListener("input", (event) => { node.port = event.target.value; node.proxyFields.port = String(node.port); renderOutput(); });
      row.querySelector(".node-note").addEventListener("input", (event) => { node.note = event.target.value; renderOutput(); });
      row.querySelector(".node-delete").addEventListener("click", () => { asset.nodes = asset.nodes.filter((item) => item.id !== node.id); render(); });
      nodeList.appendChild(row);
    });

    els.assetGrid.appendChild(card);
  });
}

function getStrategyHelp(type) {
  if (type === "url-test") return "自动测速。界面用选项卡编辑，导出 Clash 时保持 url-test。";
  if (type === "fallback") return "故障转移。按选项卡顺序尝试。";
  if (type === "load-balance") return "负载均衡。适合下载池或随机池。";
  return "手动选择。每个选项卡都可选系统项、资产库、节点或其他分流策略。";
}

function getMemberOptions(kind, currentStrategyName) {
  if (kind === "constant") return allowedConstants.map((item) => ({ value: item, label: item }));
  if (kind === "asset") return state.assets.map((item) => ({ value: item.name, label: item.name }));
  if (kind === "strategy") return state.strategies.filter((item) => item.name !== currentStrategyName).map((item) => ({ value: item.name, label: item.name }));
  if (kind === "node") return state.assets.flatMap((asset) => asset.nodes.map((node) => ({ value: node.name, label: `${node.name} · ${asset.name}` })));
  return [];
}

function fillMemberOptions(select, kind, currentStrategyName) {
  select.innerHTML = "";
  getMemberOptions(kind, currentStrategyName).forEach((option) => {
    const el = document.createElement("option");
    el.value = option.value;
    el.textContent = option.label;
    select.appendChild(el);
  });
}

function renderStrategies() {
  els.strategyEditor.innerHTML = "";
  state.strategies.forEach((strategy) => {
    const card = els.strategyTemplate.content.firstElementChild.cloneNode(true);
    card.querySelector(".strategy-name").value = strategy.name;
    card.querySelector(".strategy-type").value = strategy.type;
    card.querySelector(".strategy-help").textContent = getStrategyHelp(strategy.type);
    card.querySelector(".strategy-summary").textContent = `选项卡 ${strategy.members.length} 个`;
    card.querySelector(".strategy-name").addEventListener("input", (event) => { strategy.name = event.target.value.trim() || "未命名策略层"; render(); });
    card.querySelector(".strategy-type").addEventListener("change", (event) => { strategy.type = event.target.value; renderOutput(); });
    card.querySelector(".strategy-add-member").addEventListener("click", () => { strategy.members.push({ kind: "constant", value: "DIRECT" }); render(); });
    card.querySelector(".strategy-delete").addEventListener("click", () => { state.strategies = state.strategies.filter((item) => item.id !== strategy.id); render(); });

    const memberList = card.querySelector(".strategy-member-list");
    strategy.members.forEach((member, index) => {
      const row = els.strategyMemberTemplate.content.firstElementChild.cloneNode(true);
      const kindSelect = row.querySelector(".member-kind");
      const valueSelect = row.querySelector(".member-value");
      row.querySelector(".member-badge").textContent = `选项卡 ${index + 1}`;
      kindSelect.value = member.kind;
      fillMemberOptions(valueSelect, member.kind, strategy.name);
      valueSelect.value = member.value;
      kindSelect.addEventListener("change", (event) => { member.kind = event.target.value; member.value = getMemberOptions(member.kind, strategy.name)[0]?.value || ""; render(); });
      valueSelect.addEventListener("change", (event) => { member.value = event.target.value; renderOutput(); });
      row.querySelector(".member-delete").addEventListener("click", () => { if (strategy.members.length === 1) return; strategy.members.splice(index, 1); render(); });
      memberList.appendChild(row);
    });

    els.strategyEditor.appendChild(card);
  });
}

function renderStrategies() {
  ensureStrategyStateDefaults();
  els.strategyEditor.innerHTML = "";
  state.strategies.forEach((strategy) => {
    const card = els.strategyTemplate.content.firstElementChild.cloneNode(true);
    const toggle = card.querySelector(".strategy-toggle");
    const summary = card.querySelector(".strategy-summary");
    const providerCount = Array.isArray(strategy.providerRefs) ? strategy.providerRefs.length : 0;
    const isCollapsed = strategy.collapsed !== false;
    card.dataset.strategyId = strategy.id;
    card.classList.toggle("collapsed", isCollapsed);
    card.querySelector(".strategy-name").value = strategy.name;
    card.querySelector(".strategy-type").value = strategy.type;
    card.querySelector(".strategy-help").textContent = getStrategyHelp(strategy.type);
    summary.textContent = providerCount
      ? `成员 ${strategy.members.length} 个，Provider ${providerCount} 个`
      : `成员 ${strategy.members.length} 个`;
    toggle.textContent = isCollapsed ? "展开" : "折叠";
    toggle.addEventListener("click", () => {
      strategy.collapsed = !isCollapsed;
      render();
    });
    card.querySelector(".strategy-name").addEventListener("input", (event) => {
      strategy.name = event.target.value.trim() || "未命名策略层";
      renderStats();
      renderOutput();
    });
    card.querySelector(".strategy-type").addEventListener("change", (event) => {
      strategy.type = event.target.value;
      render();
    });
    card.querySelector(".strategy-add-member").addEventListener("click", () => {
      strategy.members.push({ kind: "constant", value: "DIRECT" });
      strategy.collapsed = false;
      render();
    });
    card.querySelector(".strategy-delete").addEventListener("click", () => {
      state.strategies = state.strategies.filter((item) => item.id !== strategy.id);
      render();
    });
    card.addEventListener("dragstart", (event) => {
      if (!event.target.closest(".strategy-drag")) {
        event.preventDefault();
        return;
      }
      draggingStrategyId = strategy.id;
      card.classList.add("dragging");
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", strategy.id);
    });
    card.addEventListener("dragend", () => {
      draggingStrategyId = null;
      card.classList.remove("dragging");
      els.strategyEditor.querySelectorAll(".strategy-card").forEach((item) => item.classList.remove("drag-over"));
    });
    card.addEventListener("dragover", (event) => {
      if (!draggingStrategyId || draggingStrategyId === strategy.id) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = "move";
      card.classList.add("drag-over");
    });
    card.addEventListener("dragleave", () => {
      card.classList.remove("drag-over");
    });
    card.addEventListener("drop", (event) => {
      if (!draggingStrategyId || draggingStrategyId === strategy.id) return;
      event.preventDefault();
      card.classList.remove("drag-over");
      moveStrategy(draggingStrategyId, strategy.id);
    });

    const memberList = card.querySelector(".strategy-member-list");
    strategy.members.forEach((member, index) => {
      const row = els.strategyMemberTemplate.content.firstElementChild.cloneNode(true);
      const kindSelect = row.querySelector(".member-kind");
      const valueSelect = row.querySelector(".member-value");
      row.querySelector(".member-badge").textContent = `成员 ${index + 1}`;
      kindSelect.value = member.kind;
      fillMemberOptions(valueSelect, member.kind, strategy.name);
      valueSelect.value = member.value;
      kindSelect.addEventListener("change", (event) => {
        member.kind = event.target.value;
        member.value = getMemberOptions(member.kind, strategy.name)[0]?.value || "";
        render();
      });
      valueSelect.addEventListener("change", (event) => {
        member.value = event.target.value;
        renderOutput();
      });
      row.querySelector(".member-delete").addEventListener("click", () => {
        if (strategy.members.length === 1) return;
        strategy.members.splice(index, 1);
        render();
      });
      memberList.appendChild(row);
    });

    els.strategyEditor.appendChild(card);
  });
}

function renderStrategies() {
  ensureStrategyStateDefaults();
  els.strategyEditor.innerHTML = "";
  state.strategies.forEach((strategy) => {
    const card = els.strategyTemplate.content.firstElementChild.cloneNode(true);
    const toggle = card.querySelector(".strategy-toggle");
    const summary = card.querySelector(".strategy-summary");
    const moveTopBtn = card.querySelector(".strategy-move-top");
    const moveUpBtn = card.querySelector(".strategy-move-up");
    const moveDownBtn = card.querySelector(".strategy-move-down");
    const providerCount = Array.isArray(strategy.providerRefs) ? strategy.providerRefs.length : 0;
    const isCollapsed = strategy.collapsed !== false;
    const strategyIndex = state.strategies.findIndex((item) => item.id === strategy.id);
    card.classList.toggle("collapsed", isCollapsed);
    card.querySelector(".strategy-name").value = strategy.name;
    card.querySelector(".strategy-type").value = strategy.type;
    card.querySelector(".strategy-help").textContent = getStrategyHelp(strategy.type);
    summary.textContent = providerCount
      ? `成员 ${strategy.members.length} 个，Provider ${providerCount} 个`
      : `成员 ${strategy.members.length} 个`;
    toggle.textContent = isCollapsed ? "展开" : "折叠";
    moveTopBtn.disabled = strategyIndex <= 0;
    moveUpBtn.disabled = strategyIndex <= 0;
    moveDownBtn.disabled = strategyIndex === -1 || strategyIndex >= state.strategies.length - 1;
    moveTopBtn.addEventListener("click", () => moveStrategyToIndex(strategy.id, 0));
    moveUpBtn.addEventListener("click", () => moveStrategyToIndex(strategy.id, strategyIndex - 1));
    moveDownBtn.addEventListener("click", () => moveStrategyToIndex(strategy.id, strategyIndex + 1));
    toggle.addEventListener("click", () => {
      strategy.collapsed = !isCollapsed;
      render();
    });
    card.querySelector(".strategy-name").addEventListener("input", (event) => {
      strategy.name = event.target.value.trim() || "未命名策略层";
      renderStats();
      renderOutput();
    });
    card.querySelector(".strategy-type").addEventListener("change", (event) => {
      strategy.type = event.target.value;
      render();
    });
    card.querySelector(".strategy-add-member").addEventListener("click", () => {
      strategy.members.push({ kind: "constant", value: "DIRECT" });
      strategy.collapsed = false;
      render();
    });
    card.querySelector(".strategy-delete").addEventListener("click", () => {
      state.strategies = state.strategies.filter((item) => item.id !== strategy.id);
      render();
    });

    const memberList = card.querySelector(".strategy-member-list");
    strategy.members.forEach((member, index) => {
      const row = els.strategyMemberTemplate.content.firstElementChild.cloneNode(true);
      const kindSelect = row.querySelector(".member-kind");
      const valueSelect = row.querySelector(".member-value");
      row.querySelector(".member-badge").textContent = `成员 ${index + 1}`;
      kindSelect.value = member.kind;
      fillMemberOptions(valueSelect, member.kind, strategy.name);
      valueSelect.value = member.value;
      kindSelect.addEventListener("change", (event) => {
        member.kind = event.target.value;
        member.value = getMemberOptions(member.kind, strategy.name)[0]?.value || "";
        render();
      });
      valueSelect.addEventListener("change", (event) => {
        member.value = event.target.value;
        renderOutput();
      });
      row.querySelector(".member-delete").addEventListener("click", () => {
        if (strategy.members.length === 1) return;
        strategy.members.splice(index, 1);
        render();
      });
      memberList.appendChild(row);
    });

    els.strategyEditor.appendChild(card);
  });
}

function renderSnifferSummary() {
  let card = els.snifferSummary.querySelector(".summary-card");
  let pre = card?.querySelector("pre");
  if (!card || !pre) {
    els.snifferSummary.innerHTML = "";
    card = document.createElement("div");
    card.className = "summary-card";
    pre = document.createElement("pre");
    card.appendChild(pre);
    els.snifferSummary.appendChild(card);
  }
  const nextText = state.rulesConfig.snifferRaw || "-";
  if (pre.textContent !== nextText) {
    pre.textContent = nextText;
  }
}

function renderSnifferEditor() {
  let card = els.snifferEditor.querySelector(".summary-card");
  let area = card?.querySelector("textarea");
  if (!card || !area) {
    els.snifferEditor.innerHTML = "";
    area = document.createElement("textarea");
    area.addEventListener("input", (event) => {
      state.rulesConfig.snifferRaw = event.target.value;
      renderSnifferSummary();
      renderOutput();
    });
    card = document.createElement("div");
    card.className = "summary-card";
    card.appendChild(area);
    els.snifferEditor.appendChild(card);
  }
  if (area.value !== state.rulesConfig.snifferRaw) {
    area.value = state.rulesConfig.snifferRaw;
  }
}

function renderProvidersSummary() {
  let card = els.providersSummary.querySelector(".summary-card");
  let pre = card?.querySelector("pre");
  if (!card || !pre) {
    els.providersSummary.innerHTML = "";
    card = document.createElement("div");
    card.className = "summary-card";
    pre = document.createElement("pre");
    card.appendChild(pre);
    els.providersSummary.appendChild(card);
  }
  const nextText = state.rulesConfig.providersRaw || "-";
  if (pre.textContent !== nextText) {
    pre.textContent = nextText;
  }
}

function renderProvidersEditor() {
  let card = els.providersEditor.querySelector(".summary-card");
  let area = card?.querySelector("textarea");
  if (!card || !area) {
    els.providersEditor.innerHTML = "";
    area = document.createElement("textarea");
    area.addEventListener("input", (event) => {
      state.rulesConfig.providersRaw = event.target.value;
      renderProvidersSummary();
      renderOutput();
    });
    card = document.createElement("div");
    card.className = "summary-card";
    card.appendChild(area);
    els.providersEditor.appendChild(card);
  }
  if (area.value !== state.rulesConfig.providersRaw) {
    area.value = state.rulesConfig.providersRaw;
  }
}

function renderRulePanels() {
  renderSnifferSummary();
  renderSnifferEditor();
  renderProvidersSummary();
  renderProvidersEditor();
}

function renderRuleList() {
  els.rulesEditor.innerHTML = "";
  state.rulesConfig.rules.forEach((rule) => {
    const row = els.ruleTemplate.content.firstElementChild.cloneNode(true);
    row.querySelector(".rule-type").value = rule.type;
    row.querySelector(".rule-value").value = rule.value;
    row.querySelector(".rule-target").value = rule.target;
    row.querySelector(".rule-type").addEventListener("change", (event) => { rule.type = event.target.value; renderOutput(); });
    row.querySelector(".rule-value").addEventListener("input", (event) => { rule.value = event.target.value; renderOutput(); });
    row.querySelector(".rule-target").addEventListener("input", (event) => { rule.target = event.target.value; ensureStrategyExists(rule.target); render(); });
    row.querySelector(".rule-delete").addEventListener("click", () => { state.rulesConfig.rules = state.rulesConfig.rules.filter((item) => item.id !== rule.id); renderRules(); renderOutput(); });
    els.rulesEditor.appendChild(row);
  });
}

function renderRules() {
  renderSnifferSummary();
  renderSnifferEditor();
  renderProvidersSummary();
  renderProvidersEditor();
  renderRuleList();
}

function formatRuleLine(rule) {
  return [rule.type, rule.value, rule.target, ...(Array.isArray(rule.tails) ? rule.tails : [])].filter(Boolean).join(",");
}

function renderRuleList() {
  ensureRuleStateDefaults();
  els.rulesEditor.innerHTML = "";
  buildRuleGroups().forEach((group) => {
    const card = document.createElement("section");
    card.className = "rule-group";

    const head = document.createElement("div");
    head.className = "rule-group-head";

    const meta = document.createElement("div");
    meta.className = "rule-group-meta";

    const groupInput = document.createElement("input");
    groupInput.className = "rule-group-name";
    groupInput.value = getRuleGroupDraft(group.id)?.name ?? group.name;
    groupInput.placeholder = "分组名称";
    groupInput.addEventListener("input", (event) => {
      setRuleGroupDraft(group.id, { name: event.target.value.trim() });
    });
    groupInput.addEventListener("input", (event) => {
      setRuleGroupDraft(group.id, { name: event.target.value.trim() });
    });
    groupInput.addEventListener("change", (event) => {
      setRuleGroupDraft(group.id, { name: event.target.value.trim() });
      return;
      setRuleGroupDraft(group.id, { name: event.target.value.trim() });
      return;
      const nextName = event.target.value.trim();
      const normalizedName = nextName || group.rules[0]?.target || "未分组";
      group.rules.forEach((rule) => {
        rule.group = normalizedName;
      });
      renderRules();
      renderOutput();
    });

    const targetSummary = document.createElement("div");
    targetSummary.className = "rule-group-targets";
    targetSummary.textContent = `目标策略：${Array.from(group.targets).filter(Boolean).join(" / ") || "未设置"} · ${group.rules.length} 条`;

    meta.append(groupInput, targetSummary);

    const actions = document.createElement("div");
    actions.className = "rule-group-actions";

    const addRuleBtn = document.createElement("button");
    addRuleBtn.type = "button";
    addRuleBtn.className = "ghost";
    addRuleBtn.textContent = "新增规则";
    addRuleBtn.addEventListener("click", () => {
      state.rulesConfig.rules.push(emptyRule({
        target: group.rules[0]?.target || "节点选择",
        group: group.name
      }));
      renderRules();
      renderOutput();
    });

    actions.appendChild(addRuleBtn);
    head.append(meta, actions);

    const body = document.createElement("div");
    body.className = "rule-group-body";

    group.rules.forEach((rule) => {
      const row = els.ruleTemplate.content.firstElementChild.cloneNode(true);
      const draft = getRuleDraft(rule.id);
      const typeInput = row.querySelector(".rule-type");
      const valueInput = row.querySelector(".rule-value");
      const targetInput = row.querySelector(".rule-target");
      row.dataset.ruleId = rule.id;
      typeInput.value = draft?.type ?? rule.type;
      valueInput.value = draft?.value ?? rule.value;
      targetInput.value = draft?.target ?? rule.target;
      typeInput.addEventListener("change", (event) => {
        setRuleDraft(rule.id, { type: event.target.value });
      });
      row.querySelector(".rule-type").addEventListener("change", (event) => {
        setRuleDraft(rule.id, { type: event.target.value });
        return;
      });
      valueInput.addEventListener("input", (event) => {
        setRuleDraft(rule.id, { value: event.target.value });
      });
      row.querySelector(".rule-value").addEventListener("input", (event) => {
        setRuleDraft(rule.id, { value: event.target.value });
        return;
      });
      targetInput.addEventListener("input", (event) => {
        setRuleDraft(rule.id, { target: event.target.value.trim() });
      });
      row.querySelector(".rule-type").addEventListener("change", (event) => {
        rule.type = event.target.value;
        renderOutput();
      });
      row.querySelector(".rule-value").addEventListener("input", (event) => {
        rule.value = event.target.value;
        renderOutput();
      });
      row.querySelector(".rule-target").addEventListener("change", (event) => {
        const previousTarget = rule.target;
        rule.target = event.target.value.trim();
        if (!rule.group || rule.group === previousTarget) {
          rule.group = rule.target || "未分组";
        }
        ensureStrategyExists(rule.target);
        renderRules();
        renderOutput();
      });
      row.querySelector(".rule-delete").addEventListener("click", () => {
        state.rulesConfig.rules = state.rulesConfig.rules.filter((item) => item.id !== rule.id);
        renderRules();
        renderOutput();
      });
      body.appendChild(row);
    });

    card.append(head, body);
    els.rulesEditor.appendChild(card);
  });
}

function renderRules() {
  renderRuleList();
}

function renderStats() {
  els.assetCount.textContent = String(state.assets.length);
  els.nodeCount.textContent = String(state.assets.reduce((sum, asset) => sum + asset.nodes.length, 0));
  els.strategyCount.textContent = String(state.strategies.length);
  els.ruleCount.textContent = String(state.rulesConfig.rules.length);
}

function buildOutputModel() {
  const assetMap = new Map(state.assets.map((asset) => [asset.name, asset]));
  const strategyMap = new Map(state.strategies.map((strategy) => [strategy.name, strategy]));
  const nodeMap = new Map(state.assets.flatMap((asset) => asset.nodes.map((node) => [node.name, node])));
  const errors = [];
  let totalResolvedNodes = 0;
  let reusedStrategies = 0;

  function resolveMember(member, owner) {
    if (member.kind === "constant") return [member.value];
    if (member.kind === "strategy") {
      if (!strategyMap.has(member.value)) errors.push(`策略「${owner}」引用的分流策略「${member.value}」不存在。`);
      reusedStrategies += 1;
      return [member.value];
    }
    if (member.kind === "node") {
      const node = nodeMap.get(member.value);
      if (!node) errors.push(`策略「${owner}」引用的节点「${member.value}」不存在。`);
      if (node && (!node.name || !node.host || !node.port)) errors.push(`节点「${node.name || "未命名节点"}」信息不完整。`);
      totalResolvedNodes += 1;
      return [member.value];
    }
    if (member.kind === "asset") {
      const asset = assetMap.get(member.value);
      if (!asset) {
        errors.push(`策略「${owner}」引用的资产库「${member.value}」不存在。`);
        return [`# Missing asset: ${member.value}`];
      }
      totalResolvedNodes += asset.nodes.length;
      return asset.nodes.map((node) => node.name);
    }
    errors.push(`策略「${owner}」存在未知选项卡类型。`);
    return ["# Unknown member kind"];
  }

  const groups = state.strategies.map((strategy) => ({
    name: strategy.name,
    type: normalizeProxyGroupType(strategy.type),
    use: Array.isArray(strategy.providerRefs) ? strategy.providerRefs.filter(Boolean) : [],
    proxies: strategy.members.flatMap((member) => resolveMember(member, strategy.name))
  }));

  state.rulesConfig.rules.forEach((rule) => {
    if (!rule.target) errors.push("存在未设置目标策略的规则。");
  });

  return { groups, errors: [...new Set(errors)], totalResolvedNodes, reusedStrategies };
}

function renderValidation(errors) {
  els.validationPanel.innerHTML = "";
  if (!errors.length) {
    const ok = document.createElement("div");
    ok.className = "validation-item ok";
    ok.textContent = "校验通过：配置、资产库、分流策略和规则引用均可解析。";
    els.validationPanel.appendChild(ok);
    return;
  }
  errors.forEach((error) => {
    const item = document.createElement("div");
    item.className = "validation-item";
    item.textContent = error;
    els.validationPanel.appendChild(item);
  });
}

function formatClash(result) {
  const config = safeYamlLoad(state.clashBaseRaw) || {};
  const sniffer = safeYamlLoad(state.rulesConfig.snifferRaw);
  const ruleProviders = safeYamlLoad(state.rulesConfig.providersRaw);
  const proxyList = state.assets.flatMap((asset) => asset.nodes.map((node) => buildProxyExportObject(node)));
  const proxyGroups = result.groups.map((group) => {
    const out = {
      name: group.name,
      type: group.type
    };
    if (group.type === "url-test") {
      out.url = "http://www.gstatic.com/generate_204";
      out.interval = 600;
    }
    if (group.use.length) out.use = group.use;
    if (group.proxies.length) out.proxies = group.proxies;
    return out;
  });
  const rules = state.rulesConfig.rules.map((rule) => [rule.type, rule.value, rule.target].filter(Boolean).join(","));

  config.sniffer = sniffer || {};
  config["rule-providers"] = ruleProviders || {};
  delete config.proxies;
  delete config["proxy-groups"];
  delete config.rules;

  const lines = [
    ...dumpYamlBlock(config),
    "",
    "proxies:"
  ];

  proxyList.forEach((proxy) => {
    lines.push(`  - ${formatInlineProxy(proxy)}`);
  });

  lines.push("", "proxy-groups:");
  dumpYamlBlock(proxyGroups).forEach((line) => lines.push(`  ${line}`));
  lines.push("", "rules:");
  dumpYamlBlock(rules).forEach((line) => lines.push(`  ${line}`));

  return lines.join("\n").trim();
}

function formatSurge(result) {
  const lines = ["[Proxy Group]"];
  result.groups.forEach((group) => {
    lines.push(`${group.name} = ${group.type}, ${group.proxies.join(", ")}`);
  });
  lines.push("", "[Rule]");
  state.rulesConfig.rules.forEach((rule) => {
    lines.push([rule.type, rule.value, rule.target].filter(Boolean).join(","));
  });
  return lines.join("\n");
}

function renderValidation(errors) {
  const firstError = Array.isArray(errors) && errors.length ? errors[0] : "";
  els.validationPanel.textContent = firstError ? `Error: ${firstError}` : "";
  els.validationPanel.classList.toggle("has-error", Boolean(firstError));
}

function appendFormattedRules(lines) {
  buildRuleGroups().forEach((group) => {
    if (group.isCustom && group.name) {
      lines.push(`  #${group.name}`);
    }
    group.rules.forEach((rule) => {
      lines.push(`  - ${formatRuleLine(rule)}`);
    });
  });
}

function formatClash(result) {
  const config = safeYamlLoad(state.clashBaseRaw) || {};
  const sniffer = safeYamlLoad(state.rulesConfig.snifferRaw);
  const ruleProviders = safeYamlLoad(state.rulesConfig.providersRaw);
  const proxyList = state.assets.flatMap((asset) => asset.nodes.map((node) => buildProxyExportObject(node)));
  const proxyGroups = result.groups.map((group) => {
    const out = {
      name: group.name,
      type: group.type
    };
    if (group.type === "url-test") {
      out.url = "http://www.gstatic.com/generate_204";
      out.interval = 600;
    }
    if (group.use.length) out.use = group.use;
    if (group.proxies.length) out.proxies = group.proxies;
    return out;
  });

  config.sniffer = sniffer || {};
  config["rule-providers"] = ruleProviders || {};
  delete config.proxies;
  delete config["proxy-groups"];
  delete config.rules;

  const lines = [
    ...dumpYamlBlock(config),
    "",
    "proxies:"
  ];

  proxyList.forEach((proxy) => {
    lines.push(`  - ${formatInlineProxy(proxy)}`);
  });

  lines.push("", "proxy-groups:");
  dumpYamlBlock(proxyGroups).forEach((line) => lines.push(`  ${line}`));
  lines.push("", "rules:");
  appendFormattedRules(lines);

  return lines.join("\n").trim();
}

function formatSurge(result) {
  const lines = ["[Proxy Group]"];
  result.groups.forEach((group) => {
    lines.push(`${group.name} = ${group.type}, ${group.proxies.join(", ")}`);
  });
  lines.push("", "[Rule]");
  buildRuleGroups().forEach((group) => {
    if (group.isCustom && group.name) {
      lines.push(`#${group.name}`);
    }
    group.rules.forEach((rule) => {
      lines.push(formatRuleLine(rule));
    });
  });
  return lines.join("\n");
}

function formatOutput(result) {
  return els.targetFormat.value === "surge" ? formatSurge(result) : formatClash(result);
}

function renderOutputNow() {
  ensureUniqueNodeNamesAcrossAssets();
  const result = buildOutputModel();
  els.resolveInfo.textContent = `已解析 ${result.totalResolvedNodes} 个叶子节点，${result.reusedStrategies} 个策略引用，${state.rulesConfig.rules.length} 条规则`;
  renderValidation(result.errors);
  els.outputPreview.textContent = formatOutput(result);
  schedulePersist();
}

function renderOutput(options = null) {
  const immediate = Boolean(options && typeof options === "object" && options.immediate);
  clearTimeout(outputRenderTimer);
  if (immediate) {
    renderOutputNow();
    return;
  }
  outputRenderTimer = setTimeout(() => {
    outputRenderTimer = null;
    renderOutputNow();
  }, 80);
}

function render() {
  renderAssets();
  renderStrategies();
  renderRulePanels();
  renderRules();
  renderStats();
  renderOutput({ immediate: true });
}

function yamlString(value) {
  return /[\s:[\]#]/.test(value) ? `"${String(value).replace(/"/g, '\\"')}"` : String(value);
}

function yamlInlineValue(value) {
  const text = String(value ?? "");
  if ((text.startsWith("{") && text.endsWith("}")) || (text.startsWith("[") && text.endsWith("]"))) {
    return text;
  }
  if (/^(true|false|null)$/i.test(text)) return text.toLowerCase();
  if (/^-?\d+(\.\d+)?$/.test(text)) return text;
  return yamlString(text);
}

function indentBlock(text) {
  return (text || "").split(/\r?\n/).filter(Boolean).map((line) => `  ${line}`);
}

function escapeHtml(text) {
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function ruleGroupWithDefaults(group = {}) {
  return {
    id: group.id || uid("rule-group"),
    name: group.name || "",
    collapsed: group.collapsed !== false,
    emitComment: Boolean(group.emitComment),
    commentLines: Array.isArray(group.commentLines) ? group.commentLines.filter(Boolean) : [],
    ruleIds: Array.isArray(group.ruleIds)
      ? group.ruleIds.filter(Boolean)
      : Array.isArray(group.rules)
        ? group.rules.map((item) => typeof item === "string" ? item : item?.id).filter(Boolean)
        : []
  };
}

function getRuleById(ruleId) {
  return state.rulesConfig.rules.find((rule) => rule.id === ruleId) || null;
}

function getRulesForGroup(group) {
  return (group.ruleIds || []).map((ruleId) => getRuleById(ruleId)).filter(Boolean);
}

function buildSequentialRuleGroups(rules) {
  const groups = [];
  let currentGroup = null;
  rules.forEach((rule) => {
    const groupName = rule.group || rule.target || "未分组";
    const emitComment = Boolean(rule.group && rule.group !== rule.target);
    if (!currentGroup || currentGroup.emitComment !== emitComment || currentGroup.name !== groupName) {
      currentGroup = ruleGroupWithDefaults({
        id: uid("rule-group"),
        name: groupName,
        collapsed: true,
        emitComment,
        commentLines: [],
        ruleIds: []
      });
      groups.push(currentGroup);
    }
    currentGroup.ruleIds.push(rule.id);
    rule.groupId = currentGroup.id;
    rule.group = currentGroup.emitComment ? currentGroup.name : (rule.target || currentGroup.name || "未分组");
  });
  return groups;
}

function syncRulesArrayFromGroups() {
  ensureRuleStateDefaults();
  state.rulesConfig.ruleGroups = Array.isArray(state.rulesConfig.ruleGroups)
    ? state.rulesConfig.ruleGroups.map((group) => ruleGroupWithDefaults(group))
    : [];
  const ruleMap = new Map(state.rulesConfig.rules.map((rule) => [rule.id, rule]));
  const orderedRules = [];
  const assigned = new Set();

  state.rulesConfig.ruleGroups.forEach((group) => {
    group.ruleIds = group.ruleIds.filter((ruleId) => ruleMap.has(ruleId));
    group.ruleIds.forEach((ruleId) => {
      const rule = ruleMap.get(ruleId);
      if (!rule) return;
      rule.groupId = group.id;
      rule.group = group.emitComment ? (group.name || rule.target || "未分组") : (rule.target || group.name || "未分组");
      orderedRules.push(rule);
      assigned.add(ruleId);
    });
  });

  state.rulesConfig.rules.forEach((rule) => {
    if (assigned.has(rule.id)) return;
    const fallbackGroup = ruleGroupWithDefaults({
      id: uid("rule-group"),
      name: rule.target || "未分组",
      collapsed: true,
      emitComment: false,
      ruleIds: [rule.id]
    });
    fallbackGroup.ruleIds = [rule.id];
    state.rulesConfig.ruleGroups.push(fallbackGroup);
    rule.groupId = fallbackGroup.id;
    rule.group = rule.target || "未分组";
    orderedRules.push(rule);
  });

  state.rulesConfig.ruleGroups = state.rulesConfig.ruleGroups.filter((group) => group.ruleIds.length);
  state.rulesConfig.rules = orderedRules;
}

function ensureRuleGroupingState() {
  ensureRuleStateDefaults();
  if (!Array.isArray(state.rulesConfig.ruleGroups) || !state.rulesConfig.ruleGroups.length) {
    state.rulesConfig.ruleGroups = buildSequentialRuleGroups(state.rulesConfig.rules);
  } else {
    state.rulesConfig.ruleGroups = state.rulesConfig.ruleGroups.map((group) => ruleGroupWithDefaults(group));
  }

  syncRulesArrayFromGroups();

  state.rulesConfig.ruleGroups.forEach((group) => {
    if (!group.emitComment) {
      const rules = getRulesForGroup(group);
      const commonTarget = rules.length && rules.every((rule) => rule.target === rules[0].target)
        ? rules[0].target
        : rules[0]?.target || group.name || "未分组";
      group.name = commonTarget || "未分组";
    }
  });

  syncRulesArrayFromGroups();
}

function buildRuleGroups() {
  ensureRuleGroupingState();
  return state.rulesConfig.ruleGroups.map((group) => {
    const rules = getRulesForGroup(group);
    return {
      ...group,
      rules,
      targets: Array.from(new Set(rules.map((rule) => rule.target).filter(Boolean)))
    };
  });
}

function createRuleGroupName(baseName = "新分组") {
  const existing = new Set(buildRuleGroups().map((group) => group.name));
  if (!existing.has(baseName)) return baseName;
  let index = 1;
  while (existing.has(`${baseName}${index}`)) index += 1;
  return `${baseName}${index}`;
}

function findRuleGroupIndex(groupId) {
  return state.rulesConfig.ruleGroups.findIndex((group) => group.id === groupId);
}

function moveRuleGroupToIndex(groupId, targetIndex) {
  ensureRuleGroupingState();
  const fromIndex = findRuleGroupIndex(groupId);
  if (fromIndex === -1) return;
  const boundedTargetIndex = Math.max(0, Math.min(targetIndex, state.rulesConfig.ruleGroups.length - 1));
  if (fromIndex === boundedTargetIndex) return;
  const [moved] = state.rulesConfig.ruleGroups.splice(fromIndex, 1);
  state.rulesConfig.ruleGroups.splice(boundedTargetIndex, 0, moved);
  syncRulesArrayFromGroups();
  renderRules();
  renderOutput();
}

function removeEmptyRuleGroups() {
  state.rulesConfig.ruleGroups = state.rulesConfig.ruleGroups.filter((group) => group.ruleIds.length);
}

function setRuleGroupDraft(groupId, patch = {}) {
  if (!groupId) return;
  const existing = ruleEditorDrafts.groups.get(groupId) || {};
  ruleEditorDrafts.groups.set(groupId, { ...existing, ...patch });
}

function getRuleGroupDraft(groupId) {
  return groupId ? (ruleEditorDrafts.groups.get(groupId) || null) : null;
}

function clearRuleGroupDraft(groupId) {
  if (!groupId) return;
  ruleEditorDrafts.groups.delete(groupId);
}

function setRuleDraft(ruleId, patch = {}) {
  if (!ruleId) return;
  const existing = ruleEditorDrafts.rules.get(ruleId) || {};
  ruleEditorDrafts.rules.set(ruleId, { ...existing, ...patch });
}

function getRuleDraft(ruleId) {
  return ruleId ? (ruleEditorDrafts.rules.get(ruleId) || null) : null;
}

function clearRuleDraft(ruleId) {
  if (!ruleId) return;
  ruleEditorDrafts.rules.delete(ruleId);
}

function clearRuleEditorDrafts() {
  ruleEditorDrafts.groups.clear();
  ruleEditorDrafts.rules.clear();
}

function syncRuleEditorDraftsFromDom() {
  if (!els.rulesEditor) return;
  els.rulesEditor.querySelectorAll(".rule-group").forEach((groupCard) => {
    const groupId = groupCard.dataset.groupId;
    const groupNameInput = groupCard.querySelector(".rule-group-name");
    if (groupId && groupNameInput) {
      setRuleGroupDraft(groupId, { name: groupNameInput.value.trim() });
    }
    groupCard.querySelectorAll(".rule-row").forEach((row) => {
      const ruleId = row.dataset.ruleId;
      if (!ruleId) return;
      setRuleDraft(ruleId, {
        type: row.querySelector(".rule-type")?.value || "MATCH",
        value: row.querySelector(".rule-value")?.value || "",
        target: row.querySelector(".rule-target")?.value.trim() || "节点选择"
      });
    });
  });
}

function commitRuleEditorDrafts() {
  ensureRuleGroupingState();
  syncRuleEditorDraftsFromDom();
  const groupCards = Array.from(els.rulesEditor?.querySelectorAll(".rule-group") || []);
  if (!groupCards.length) {
    clearRuleEditorDrafts();
    return;
  }

  const groupMap = new Map(state.rulesConfig.ruleGroups.map((group) => [group.id, ruleGroupWithDefaults(group)]));
  const ruleMap = new Map(state.rulesConfig.rules.map((rule) => [rule.id, ruleWithDefaults(rule)]));
  const nextGroups = [];
  const nextRules = [];

  groupCards.forEach((groupCard) => {
    const sourceGroup = ruleGroupWithDefaults(groupMap.get(groupCard.dataset.groupId) || { id: groupCard.dataset.groupId || uid("rule-group") });
    const rows = Array.from(groupCard.querySelectorAll(".rule-row"));
    if (!rows.length) return;

    const draftedRules = rows.map((row) => {
      const ruleId = row.dataset.ruleId || uid("rule");
      const baseRule = ruleWithDefaults(ruleMap.get(ruleId) || { id: ruleId });
      return ruleWithDefaults({
        ...baseRule,
        id: ruleId,
        type: row.querySelector(".rule-type")?.value || baseRule.type,
        value: row.querySelector(".rule-value")?.value || "",
        target: row.querySelector(".rule-target")?.value.trim() || "节点选择"
      });
    });

    const enteredGroupName = groupCard.querySelector(".rule-group-name")?.value.trim() || "";
    const commonTarget = draftedRules.length && draftedRules.every((rule) => rule.target === draftedRules[0].target)
      ? draftedRules[0].target
      : draftedRules[0]?.target || sourceGroup.name || "未分组";
    const emitComment = Boolean(enteredGroupName && enteredGroupName !== commonTarget);

    if (emitComment) {
      const nextGroup = ruleGroupWithDefaults({
        id: sourceGroup.id,
        name: enteredGroupName,
        collapsed: sourceGroup.collapsed,
        emitComment: true,
        commentLines: [enteredGroupName],
        ruleIds: []
      });
      draftedRules.forEach((rule) => {
        ensureStrategyExists(rule.target);
        rule.groupId = nextGroup.id;
        rule.group = nextGroup.name;
        nextGroup.ruleIds.push(rule.id);
        nextRules.push(rule);
      });
      nextGroups.push(nextGroup);
      return;
    }

    let currentGroup = null;
    draftedRules.forEach((rule, index) => {
      ensureStrategyExists(rule.target);
      const autoName = rule.target || "未分组";
      if (!currentGroup || currentGroup.name !== autoName) {
        currentGroup = ruleGroupWithDefaults({
          id: !nextGroups.some((group) => group.id === sourceGroup.id) && index === 0 ? sourceGroup.id : uid("rule-group"),
          name: autoName,
          collapsed: sourceGroup.collapsed,
          emitComment: false,
          commentLines: [],
          ruleIds: []
        });
        nextGroups.push(currentGroup);
      }
      rule.groupId = currentGroup.id;
      rule.group = autoName;
      currentGroup.ruleIds.push(rule.id);
      nextRules.push(rule);
    });
  });

  state.rulesConfig.ruleGroups = nextGroups;
  state.rulesConfig.rules = nextRules;
  removeEmptyRuleGroups();
  syncRulesArrayFromGroups();
  clearRuleEditorDrafts();
}

function createRuleGroupAtTop({ name, emitComment, target = "节点选择" }) {
  ensureRuleGroupingState();
  const group = ruleGroupWithDefaults({
    id: uid("rule-group"),
    name: emitComment ? name : target,
    collapsed: false,
    emitComment,
    commentLines: emitComment ? [name] : [],
    ruleIds: []
  });
  const rule = ruleWithDefaults({
    id: uid("rule"),
    type: "MATCH",
    value: "",
    target,
    group: emitComment ? name : target
  });
  rule.groupId = group.id;
  group.ruleIds.unshift(rule.id);
  state.rulesConfig.ruleGroups.unshift(group);
  state.rulesConfig.rules.unshift(rule);
  ensureStrategyExists(target);
  syncRulesArrayFromGroups();
  renderRules();
  renderOutput();
}

function extractRulesSectionLines(text) {
  const lines = String(text || "").split(/\r?\n/);
  const rulesIndex = lines.findIndex((line) => /^rules:\s*$/.test(line.trim()));
  if (rulesIndex === -1) return [];
  return lines.slice(rulesIndex + 1);
}

function parseRuleLine(line) {
  const parsed = splitRuleParts(line.replace(/^- /, ""));
  return ruleWithDefaults({ id: uid("rule"), ...parsed });
}

function importRulesLayoutFromText(text, fallbackRules = []) {
  const sectionLines = extractRulesSectionLines(text);
  const groups = [];
  const rules = [];
  let pendingComments = [];
  let currentGroup = null;

  if (sectionLines.length) {
    sectionLines.forEach((rawLine) => {
      const trimmed = rawLine.trim();
      if (!trimmed) return;
      if (/^#/.test(trimmed)) {
        const comment = trimmed.replace(/^#+\s*/, "").trim();
        if (comment) pendingComments.push(comment);
        currentGroup = null;
        return;
      }
      if (!trimmed.startsWith("- ")) return;

      const rule = parseRuleLine(trimmed);
      ensureStrategyExists(rule.target);

      if (pendingComments.length) {
        if (!currentGroup) {
          currentGroup = ruleGroupWithDefaults({
            id: uid("rule-group"),
            name: pendingComments.join(" / ") || "规则分组",
            collapsed: true,
            emitComment: true,
            commentLines: pendingComments.slice(),
            ruleIds: []
          });
          groups.push(currentGroup);
        }
      } else {
        const autoName = rule.target || "未分组";
        if (!currentGroup || currentGroup.emitComment || currentGroup.name !== autoName) {
          currentGroup = ruleGroupWithDefaults({
            id: uid("rule-group"),
            name: autoName,
            collapsed: true,
            emitComment: false,
            ruleIds: []
          });
          groups.push(currentGroup);
        }
      }

      rule.groupId = currentGroup.id;
      rule.group = currentGroup.emitComment ? currentGroup.name : (rule.target || currentGroup.name || "未分组");
      currentGroup.ruleIds.push(rule.id);
      rules.push(rule);
      pendingComments = [];
    });
  } else if (Array.isArray(fallbackRules) && fallbackRules.length) {
    fallbackRules.forEach((entry) => {
      const parsed = splitRuleParts(entry);
      ensureStrategyExists(parsed.target);
      rules.push(ruleWithDefaults({ id: uid("rule"), ...parsed }));
    });
    groups.push(...buildSequentialRuleGroups(rules));
  }

  state.rulesConfig.rules = rules;
  state.rulesConfig.ruleGroups = groups;
  ensureRuleGroupingState();
}

function snapshotState() {
  return {
    importedConfigPath: state.importedConfigPath,
    lastSavedConfigPath: state.lastSavedConfigPath,
    exportVersion: state.exportVersion,
    rawInput: els.rawInput.value,
    clashConfigInput: els.clashConfigInput.value,
    targetFormat: els.targetFormat.value,
    configExportName: els.configExportName.value,
    state: {
      assets: state.assets,
      strategies: state.strategies,
      clashBaseRaw: state.clashBaseRaw,
      rulesConfig: {
        ...state.rulesConfig,
        ruleGroups: Array.isArray(state.rulesConfig.ruleGroups) ? state.rulesConfig.ruleGroups : []
      }
    }
  };
}

function hydrateFromSnapshot(snapshot) {
  if (!snapshot || !snapshot.state) return false;
  state.importedConfigPath = snapshot.importedConfigPath || "";
  state.lastSavedConfigPath = snapshot.lastSavedConfigPath || "";
  state.exportVersion = Number.isInteger(snapshot.exportVersion) ? snapshot.exportVersion : 0;
  state.assets = Array.isArray(snapshot.state.assets) ? snapshot.state.assets : [];
  state.strategies = Array.isArray(snapshot.state.strategies) ? snapshot.state.strategies.map(strategyWithDefaults) : [];
  state.clashBaseRaw = normalizeYamlDumpText(snapshot.state.clashBaseRaw || defaultClashBaseRaw);
  state.rulesConfig = {
    snifferRaw: normalizeYamlDumpText(snapshot.state.rulesConfig?.snifferRaw || defaultSnifferRaw),
    providersRaw: snapshot.state.rulesConfig?.providersRaw || defaultProvidersRaw,
    rules: Array.isArray(snapshot.state.rulesConfig?.rules) ? snapshot.state.rulesConfig.rules.map((rule) => ruleWithDefaults(rule)) : [],
    ruleGroups: Array.isArray(snapshot.state.rulesConfig?.ruleGroups) ? snapshot.state.rulesConfig.ruleGroups.map((group) => ruleGroupWithDefaults(group)) : []
  };
  state.nodes = state.assets.flatMap((asset) => Array.isArray(asset.nodes) ? asset.nodes : []);
  ensureRuleGroupingState();
  els.rawInput.value = snapshot.rawInput || "";
  els.clashConfigInput.value = snapshot.clashConfigInput || getDefaultConfigText();
  els.targetFormat.value = snapshot.targetFormat || "clash";
  els.configExportName.value = snapshot.configExportName || "";
  return true;
}

function importTemplateDb(text) {
  try {
    const data = JSON.parse(text);
    if (data.rulesConfig) {
      state.rulesConfig.snifferRaw = data.rulesConfig.snifferRaw || state.rulesConfig.snifferRaw;
      state.rulesConfig.providersRaw = data.rulesConfig.providersRaw || state.rulesConfig.providersRaw;
      state.rulesConfig.rules = Array.isArray(data.rulesConfig.rules) ? data.rulesConfig.rules.map((rule) => ruleWithDefaults(rule)) : [];
      state.rulesConfig.ruleGroups = Array.isArray(data.rulesConfig.ruleGroups) ? data.rulesConfig.ruleGroups.map((group) => ruleGroupWithDefaults(group)) : [];
      ensureRuleGroupingState();
    }
    if (Array.isArray(data.strategies)) {
      state.strategies = data.strategies.map((strategy) => strategyWithDefaults({
        id: uid("strategy"),
        name: strategy.name,
        type: strategy.type || "select",
        members: Array.isArray(strategy.members) && strategy.members.length ? strategy.members : [{ kind: "constant", value: "DIRECT" }]
      }));
    }
  } catch {
    return;
  }
}

function exportTemplateDb() {
  ensureRuleGroupingState();
  const ruleTargets = new Set(
    state.rulesConfig.rules
      .map((rule) => rule.target)
      .filter((target) => target && !allowedConstants.includes(target))
  );
  const payload = {
    rulesConfig: {
      snifferRaw: state.rulesConfig.snifferRaw,
      providersRaw: state.rulesConfig.providersRaw,
      rules: state.rulesConfig.rules,
      ruleGroups: state.rulesConfig.ruleGroups
    },
    strategies: state.strategies.map((strategy) => ({
      name: strategy.name,
      type: strategy.type,
      members: [{ kind: "constant", value: "DIRECT" }]
    })).filter((strategy) => ruleTargets.has(strategy.name))
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "proxy-template.db";
  link.click();
  URL.revokeObjectURL(url);
}

function importRulesConfig(text) {
  const lines = text.split(/\r?\n/);
  let section = "";
  const snifferLines = [];
  const providerLines = [];

  lines.forEach((rawLine) => {
    const line = rawLine.trim();
    if (!line) return;
    if (line === "sniffer:") {
      section = "sniffer";
      return;
    }
    if (line === "rule-providers:") {
      section = "providers";
      return;
    }
    if (line === "rules:") {
      section = "rules";
      return;
    }

    if (section === "sniffer") {
      snifferLines.push(rawLine.replace(/^\s{2}/, ""));
      return;
    }

    if (section === "providers") {
      providerLines.push(rawLine.replace(/^\s{2}/, ""));
    }
  });

  state.rulesConfig.snifferRaw = snifferLines.join("\n");
  state.rulesConfig.providersRaw = providerLines.join("\n");
  importRulesLayoutFromText(text);
}

function importClashConfig(text) {
  const parsedConfig = safeYamlLoad(text);
  if (parsedConfig && typeof parsedConfig === "object" && !Array.isArray(parsedConfig)) {
    const baseConfig = { ...parsedConfig };
    delete baseConfig.sniffer;
    delete baseConfig["rule-providers"];
    delete baseConfig.proxies;
    delete baseConfig["proxy-groups"];
    delete baseConfig.rules;

    state.assets = [];
    state.nodes = [];
    state.strategies = [];
    state.rulesConfig.rules = [];
    state.rulesConfig.ruleGroups = [];
    state.clashBaseRaw = dumpYaml(baseConfig) || state.clashBaseRaw;
    state.rulesConfig.snifferRaw = dumpYaml(parsedConfig.sniffer) || "";
    state.rulesConfig.providersRaw = dumpYaml(parsedConfig["rule-providers"]) || "";

    if (Array.isArray(parsedConfig.proxies) && parsedConfig.proxies.length) {
      const proxies = parsedConfig.proxies.map((proxy) => ({ ...proxy, raw: "" }));
      state.assets = buildAssetsFromImportedProxies(proxies);
      state.nodes = state.assets.flatMap((asset) => asset.nodes);
      ensureUniqueNodeNamesAcrossAssets();
    }

    importProxyGroupsFromConfig(parsedConfig["proxy-groups"]);
    importRulesLayoutFromText(text, parsedConfig.rules);
    return;
  }

  const lines = text.split(/\r?\n/);
  const snifferIndex = lines.findIndex((line) => /^sniffer:\s*$/.test(line.trim()));
  const providersIndex = lines.findIndex((line) => /^rule-providers:\s*$/.test(line.trim()));
  const proxiesIndex = lines.findIndex((line) => /^proxies:\s*$/.test(line.trim()));
  const proxyGroupsIndex = lines.findIndex((line) => /^proxy-groups:\s*$/.test(line.trim()));
  const rulesIndex = lines.findIndex((line) => /^rules:\s*$/.test(line.trim()));

  const cutIndexes = [snifferIndex, providersIndex, proxiesIndex, proxyGroupsIndex, rulesIndex].filter((index) => index !== -1);
  const firstCut = cutIndexes.length ? Math.min(...cutIndexes) : lines.length;

  state.assets = [];
  state.nodes = [];
  state.strategies = [];
  state.rulesConfig.rules = [];
  state.rulesConfig.ruleGroups = [];
  state.clashBaseRaw = lines.slice(0, firstCut).join("\n").trim() || state.clashBaseRaw;

  if (snifferIndex !== -1) {
    state.rulesConfig.snifferRaw = collectSection(
      lines,
      snifferIndex + 1,
      [/^rule-providers:\s*$/, /^proxy-groups:\s*$/, /^rules:\s*$/]
    ).map((line) => line.replace(/^\s{2}/, "")).join("\n").trim();
  }

  if (providersIndex !== -1) {
    state.rulesConfig.providersRaw = collectSection(
      lines,
      providersIndex + 1,
      [/^proxies:\s*$/, /^proxy-groups:\s*$/, /^rules:\s*$/]
    ).map((line) => line.replace(/^\s{2}/, "")).join("\n").trim();
  }

  if (proxiesIndex !== -1) {
    const proxyLines = collectSection(
      lines,
      proxiesIndex + 1,
      [/^proxy-groups:\s*$/, /^rules:\s*$/]
    ).filter((line) => line.trim().startsWith("- {"));
    const proxies = proxyLines.map((line) => {
      const parsed = parseInlineProxyMap(line.trim());
      return {
        ...parsed,
        raw: line.trim().replace(/^- /, "")
      };
    });
    if (proxies.length) {
      state.assets = buildAssetsFromImportedProxies(proxies);
      state.nodes = state.assets.flatMap((asset) => asset.nodes);
    }
  }

  if (proxyGroupsIndex !== -1) {
    importProxyGroups(lines.slice(proxyGroupsIndex + 1, rulesIndex === -1 ? lines.length : rulesIndex));
  }

  importRulesLayoutFromText(text);
}

function renderRuleList() {
  ensureRuleGroupingState();
  els.rulesEditor.innerHTML = "";
  buildRuleGroups().forEach((group) => {
    const card = document.createElement("section");
    card.className = "rule-group";
    card.dataset.groupId = group.id;
    card.classList.toggle("collapsed", group.collapsed !== false);

    const head = document.createElement("div");
    head.className = "rule-group-head";

    const meta = document.createElement("div");
    meta.className = "rule-group-meta";

    const groupInput = document.createElement("input");
    groupInput.className = "rule-group-name";
    groupInput.value = getRuleGroupDraft(group.id)?.name ?? group.name;
    groupInput.placeholder = "分组名称";
    groupInput.addEventListener("change", (event) => {
      const nextName = event.target.value.trim();
      const currentGroup = state.rulesConfig.ruleGroups.find((item) => item.id === group.id);
      if (!currentGroup) return;
      const currentRules = getRulesForGroup(currentGroup);
      const commonTarget = currentRules.length && currentRules.every((rule) => rule.target === currentRules[0].target)
        ? currentRules[0].target
        : currentRules[0]?.target || "未分组";
      currentGroup.emitComment = Boolean(nextName && nextName !== commonTarget);
      currentGroup.name = currentGroup.emitComment ? nextName : commonTarget;
      currentGroup.commentLines = currentGroup.emitComment ? [currentGroup.name] : [];
      syncRulesArrayFromGroups();
      renderRules();
      renderOutput();
    });

    const targetSummary = document.createElement("div");
    targetSummary.className = "rule-group-targets";
    targetSummary.textContent = `目标策略：${group.targets.join(" / ") || "未设置"} · ${group.rules.length} 条`;

    meta.append(groupInput, targetSummary);

    const actions = document.createElement("div");
    actions.className = "rule-group-actions";

    const topBtn = document.createElement("button");
    topBtn.type = "button";
    topBtn.className = "ghost";
    topBtn.textContent = "置顶";
    topBtn.disabled = findRuleGroupIndex(group.id) <= 0;
    topBtn.addEventListener("click", () => moveRuleGroupToIndex(group.id, 0));

    const upBtn = document.createElement("button");
    upBtn.type = "button";
    upBtn.className = "ghost";
    upBtn.textContent = "上移";
    upBtn.disabled = findRuleGroupIndex(group.id) <= 0;
    upBtn.addEventListener("click", () => moveRuleGroupToIndex(group.id, findRuleGroupIndex(group.id) - 1));

    const downBtn = document.createElement("button");
    downBtn.type = "button";
    downBtn.className = "ghost";
    downBtn.textContent = "下移";
    downBtn.disabled = findRuleGroupIndex(group.id) >= state.rulesConfig.ruleGroups.length - 1;
    downBtn.addEventListener("click", () => moveRuleGroupToIndex(group.id, findRuleGroupIndex(group.id) + 1));

    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "ghost";
    toggleBtn.textContent = group.collapsed !== false ? "展开" : "折叠";
    toggleBtn.addEventListener("click", () => {
      const currentGroup = state.rulesConfig.ruleGroups.find((item) => item.id === group.id);
      if (!currentGroup) return;
      currentGroup.collapsed = !(currentGroup.collapsed !== false);
      renderRules();
    });

    const addRuleBtn = document.createElement("button");
    addRuleBtn.type = "button";
    addRuleBtn.className = "ghost";
    addRuleBtn.textContent = "新增规则";
    addRuleBtn.addEventListener("click", () => {
      const currentGroup = state.rulesConfig.ruleGroups.find((item) => item.id === group.id);
      if (!currentGroup) return;
      const rule = ruleWithDefaults({
        id: uid("rule"),
        target: group.rules[0]?.target || "节点选择",
        group: currentGroup.emitComment ? currentGroup.name : (group.rules[0]?.target || "节点选择")
      });
      rule.groupId = currentGroup.id;
      currentGroup.ruleIds.push(rule.id);
      state.rulesConfig.rules.push(rule);
      syncRulesArrayFromGroups();
      renderRules();
      renderStats();
    });

    actions.append(topBtn, upBtn, downBtn, toggleBtn, addRuleBtn);
    head.append(meta, actions);

    const body = document.createElement("div");
    body.className = "rule-group-body";

    group.rules.forEach((rule) => {
      const row = els.ruleTemplate.content.firstElementChild.cloneNode(true);
      const draft = getRuleDraft(rule.id);
      const typeInput = row.querySelector(".rule-type");
      const valueInput = row.querySelector(".rule-value");
      const targetInput = row.querySelector(".rule-target");
      row.dataset.ruleId = rule.id;
      typeInput.value = draft?.type ?? rule.type;
      valueInput.value = draft?.value ?? rule.value;
      targetInput.value = draft?.target ?? rule.target;
      typeInput.addEventListener("change", (event) => {
        setRuleDraft(rule.id, { type: event.target.value });
      });
      row.querySelector(".rule-type").addEventListener("change", (event) => {
        setRuleDraft(rule.id, { type: event.target.value });
        return;
        rule.type = event.target.value;
        renderOutput();
      });
      valueInput.addEventListener("input", (event) => {
        setRuleDraft(rule.id, { value: event.target.value });
      });
      row.querySelector(".rule-value").addEventListener("input", (event) => {
        setRuleDraft(rule.id, { value: event.target.value });
        return;
        rule.value = event.target.value;
        renderOutput();
      });
      targetInput.addEventListener("input", (event) => {
        setRuleDraft(rule.id, { target: event.target.value.trim() });
      });
      row.querySelector(".rule-target").addEventListener("change", (event) => {
        setRuleDraft(rule.id, { target: event.target.value.trim() });
        return;
        const nextTarget = event.target.value.trim();
        const currentGroup = state.rulesConfig.ruleGroups.find((item) => item.id === rule.groupId);
        if (!currentGroup) return;
        rule.target = nextTarget;
        ensureStrategyExists(rule.target);
        if (!currentGroup.emitComment) {
          const currentIndex = findRuleGroupIndex(currentGroup.id);
          currentGroup.ruleIds = currentGroup.ruleIds.filter((ruleId) => ruleId !== rule.id);
          removeEmptyRuleGroups();
          const nextGroup = ruleGroupWithDefaults({
            id: uid("rule-group"),
            name: rule.target || "未分组",
            collapsed: false,
            emitComment: false,
            commentLines: [],
            ruleIds: [rule.id]
          });
          rule.groupId = nextGroup.id;
          rule.group = rule.target || "未分组";
          state.rulesConfig.ruleGroups.splice(Math.max(0, currentIndex), 0, nextGroup);
        } else {
          rule.group = currentGroup.name;
        }
        syncRulesArrayFromGroups();
        renderRules();
        renderOutput();
      });
      row.querySelector(".rule-delete").addEventListener("click", () => {
        const currentGroup = state.rulesConfig.ruleGroups.find((item) => item.id === rule.groupId);
        if (currentGroup) {
          currentGroup.ruleIds = currentGroup.ruleIds.filter((ruleId) => ruleId !== rule.id);
        }
        state.rulesConfig.rules = state.rulesConfig.rules.filter((item) => item.id !== rule.id);
        clearRuleDraft(rule.id);
        removeEmptyRuleGroups();
        syncRulesArrayFromGroups();
        renderRules();
        renderStats();
      });
      body.appendChild(row);
    });

    card.append(head, body);
    els.rulesEditor.appendChild(card);
  });
}

function renderRules() {
  renderRuleList();
}

function renderRuleList() {
  ensureRuleGroupingState();
  els.rulesEditor.innerHTML = "";
  buildRuleGroups().forEach((group) => {
    const card = document.createElement("section");
    card.className = "rule-group";
    card.dataset.groupId = group.id;
    card.classList.toggle("collapsed", group.collapsed !== false);

    const head = document.createElement("div");
    head.className = "rule-group-head";

    const meta = document.createElement("div");
    meta.className = "rule-group-meta";

    const groupInput = document.createElement("input");
    groupInput.className = "rule-group-name";
    groupInput.value = getRuleGroupDraft(group.id)?.name ?? group.name;
    groupInput.placeholder = "规则分组名称";
    groupInput.addEventListener("input", (event) => {
      setRuleGroupDraft(group.id, { name: event.target.value.trim() });
    });

    const targetSummary = document.createElement("div");
    targetSummary.className = "rule-group-targets";
    targetSummary.textContent = `目标策略: ${group.targets.join(" / ") || "未设置"} | ${group.rules.length} 条`;

    meta.append(groupInput, targetSummary);

    const actions = document.createElement("div");
    actions.className = "rule-group-actions";

    const topBtn = document.createElement("button");
    topBtn.type = "button";
    topBtn.className = "ghost";
    topBtn.textContent = "置顶";
    topBtn.disabled = findRuleGroupIndex(group.id) <= 0;
    topBtn.addEventListener("click", () => moveRuleGroupToIndex(group.id, 0));

    const upBtn = document.createElement("button");
    upBtn.type = "button";
    upBtn.className = "ghost";
    upBtn.textContent = "上移";
    upBtn.disabled = findRuleGroupIndex(group.id) <= 0;
    upBtn.addEventListener("click", () => moveRuleGroupToIndex(group.id, findRuleGroupIndex(group.id) - 1));

    const downBtn = document.createElement("button");
    downBtn.type = "button";
    downBtn.className = "ghost";
    downBtn.textContent = "下移";
    downBtn.disabled = findRuleGroupIndex(group.id) >= state.rulesConfig.ruleGroups.length - 1;
    downBtn.addEventListener("click", () => moveRuleGroupToIndex(group.id, findRuleGroupIndex(group.id) + 1));

    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "ghost";
    toggleBtn.textContent = group.collapsed !== false ? "展开" : "折叠";
    toggleBtn.addEventListener("click", () => {
      const currentGroup = state.rulesConfig.ruleGroups.find((item) => item.id === group.id);
      if (!currentGroup) return;
      currentGroup.collapsed = !(currentGroup.collapsed !== false);
      renderRules();
    });

    const addRuleBtn = document.createElement("button");
    addRuleBtn.type = "button";
    addRuleBtn.className = "ghost";
    addRuleBtn.textContent = "新增规则";
    addRuleBtn.addEventListener("click", () => {
      const currentGroup = state.rulesConfig.ruleGroups.find((item) => item.id === group.id);
      if (!currentGroup) return;
      const rule = ruleWithDefaults({
        id: uid("rule"),
        target: group.rules[0]?.target || "节点选择",
        group: currentGroup.emitComment ? currentGroup.name : (group.rules[0]?.target || "节点选择")
      });
      rule.groupId = currentGroup.id;
      currentGroup.ruleIds.push(rule.id);
      state.rulesConfig.rules.push(rule);
      syncRulesArrayFromGroups();
      renderRules();
      renderStats();
    });

    actions.append(topBtn, upBtn, downBtn, toggleBtn, addRuleBtn);
    head.append(meta, actions);

    const body = document.createElement("div");
    body.className = "rule-group-body";

    group.rules.forEach((rule) => {
      const row = els.ruleTemplate.content.firstElementChild.cloneNode(true);
      const draft = getRuleDraft(rule.id);
      const typeInput = row.querySelector(".rule-type");
      const valueInput = row.querySelector(".rule-value");
      const targetInput = row.querySelector(".rule-target");
      row.dataset.ruleId = rule.id;
      typeInput.value = draft?.type ?? rule.type;
      valueInput.value = draft?.value ?? rule.value;
      targetInput.value = draft?.target ?? rule.target;
      typeInput.addEventListener("change", (event) => {
        setRuleDraft(rule.id, { type: event.target.value });
      });
      valueInput.addEventListener("input", (event) => {
        setRuleDraft(rule.id, { value: event.target.value });
      });
      targetInput.addEventListener("input", (event) => {
        setRuleDraft(rule.id, { target: event.target.value.trim() });
      });
      row.querySelector(".rule-delete").addEventListener("click", () => {
        const currentGroup = state.rulesConfig.ruleGroups.find((item) => item.id === rule.groupId);
        if (currentGroup) {
          currentGroup.ruleIds = currentGroup.ruleIds.filter((ruleId) => ruleId !== rule.id);
          if (!currentGroup.ruleIds.length) {
            clearRuleGroupDraft(currentGroup.id);
          }
        }
        state.rulesConfig.rules = state.rulesConfig.rules.filter((item) => item.id !== rule.id);
        clearRuleDraft(rule.id);
        removeEmptyRuleGroups();
        syncRulesArrayFromGroups();
        renderRules();
        renderStats();
      });
      body.appendChild(row);
    });

    card.append(head, body);
    els.rulesEditor.appendChild(card);
  });
}

function appendFormattedRules(lines) {
  buildRuleGroups().forEach((group) => {
    if (group.emitComment && group.name) {
      const comments = Array.isArray(group.commentLines) && group.commentLines.length ? group.commentLines : [group.name];
      comments.forEach((comment) => {
        lines.push(`  #${comment}`);
      });
    }
    group.rules.forEach((rule) => {
      lines.push(`  - ${formatRuleLine(rule)}`);
    });
  });
}

async function confirmAndSaveWorkspace() {
  commitRuleEditorDrafts();
  render();
  clearTimeout(persistTimer);

  if (!window.desktopAPI?.saveSession) return;

  const button = els.saveWorkspaceBtn;
  const originalLabel = button?.dataset.defaultLabel || button?.textContent || "确认并保存";

  if (button) {
    button.dataset.defaultLabel = originalLabel;
    button.classList.add("is-saving");
    button.textContent = "保存中...";
  }

  try {
    await window.desktopAPI.saveSession(snapshotState());
    if (button) {
      button.textContent = "已保存";
    }
  } catch {
    if (button) {
      button.textContent = "保存失败";
    }
  } finally {
    setTimeout(() => {
      if (!button) return;
      button.classList.remove("is-saving");
      button.textContent = originalLabel;
    }, 1200);
  }
}

async function boot() {
  bindEvents();

  if (els.addRuleBtn) {
    const addRuleBtn = els.addRuleBtn.cloneNode(true);
    els.addRuleBtn.replaceWith(addRuleBtn);
    els.addRuleBtn = addRuleBtn;
    els.addRuleBtn.addEventListener("click", () => {
      createRuleGroupAtTop({ name: "节点选择", emitComment: false, target: "节点选择" });
    });
  }

  if (els.addRuleGroupBtn) {
    const addRuleGroupBtn = els.addRuleGroupBtn.cloneNode(true);
    els.addRuleGroupBtn.replaceWith(addRuleGroupBtn);
    els.addRuleGroupBtn = addRuleGroupBtn;
    els.addRuleGroupBtn.addEventListener("click", () => {
      createRuleGroupAtTop({ name: createRuleGroupName(), emitComment: true, target: "节点选择" });
    });
  }

  if (els.saveWorkspaceBtn) {
    const saveWorkspaceBtn = els.saveWorkspaceBtn.cloneNode(true);
    els.saveWorkspaceBtn.replaceWith(saveWorkspaceBtn);
    els.saveWorkspaceBtn = saveWorkspaceBtn;
    els.saveWorkspaceBtn.addEventListener("click", () => {
      confirmAndSaveWorkspace().catch(() => {});
    });
  }

  if (els.appVersionLabel) {
    const version = window.desktopAPI?.getAppVersion
      ? await window.desktopAPI.getAppVersion().catch(() => "")
      : "";
    els.appVersionLabel.textContent = version ? `Version ${version}` : "Version";
  }

  const restored = window.desktopAPI?.loadSession
    ? await window.desktopAPI.loadSession().catch(() => null)
    : null;

  if (hydrateFromSnapshot(restored)) {
    render();
    return;
  }

  els.rawInput.value = sampleRawInput;
  els.clashConfigInput.value = getDefaultConfigText();
  seedDemoData();
  render();
}

async function bootLegacy() {
  bindEvents();
  if (els.appVersionLabel) {
    const version = window.desktopAPI?.getAppVersion
      ? await window.desktopAPI.getAppVersion().catch(() => "")
      : "";
    els.appVersionLabel.textContent = version ? `Version ${version}` : "Version";
  }

  const restored = window.desktopAPI?.loadSession
    ? await window.desktopAPI.loadSession().catch(() => null)
    : null;

  if (hydrateFromSnapshot(restored)) {
    render();
    return;
  }

  els.rawInput.value = sampleRawInput;
  els.clashConfigInput.value = getDefaultConfigText();
  seedDemoData();
  render();
  return;
  els.clashConfigInput.value = [
    "port: 7890",
    "socks-port: 7891",
    "allow-lan: true",
    "unified-delay: true",
    "mode: Rule",
    "log-level: info",
    "external-controller: :9090",
    "dns:",
    "  enable: true",
    "  nameserver:",
    "    - 119.29.29.29",
    "    - 223.5.5.5",
    "  fallback:",
    "    - 8.8.8.8",
    "    - 8.8.4.4",
    "    - tls://1.0.0.1:853",
    "    - tls://dns.google:853",
    "",
    "sniffer:",
    ...indentBlock(state.rulesConfig.snifferRaw),
    "",
    "rule-providers:",
    ...indentBlock(state.rulesConfig.providersRaw),
    "",
    "proxy-groups:",
    "  - name: 节点选择",
    "    type: select",
    "    proxies:",
    "      - DIRECT",
    "",
    "rules:",
    "  - MATCH,节点选择"
  ].join("\n");
  seedDemoData();
  bindEvents();
  render();
}

boot();
