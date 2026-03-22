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
  assetTemplate: document.querySelector("#assetTemplate"),
  assetNodeTemplate: document.querySelector("#assetNodeTemplate"),
  strategyTemplate: document.querySelector("#strategyTemplate"),
  strategyMemberTemplate: document.querySelector("#strategyMemberTemplate"),
  providerTemplate: document.querySelector("#providerTemplate"),
  ruleTemplate: document.querySelector("#ruleTemplate")
};

function uid(prefix) {
  return `${prefix}-${Math.random().toString(36).slice(2, 8)}`;
}

function emptyNode(protocol = "ss") {
  return { id: uid("node"), name: "", host: "", port: "", protocol, note: "", raw: "" };
}

function emptyRule() {
  return { id: uid("rule"), type: "MATCH", value: "", target: "节点选择" };
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
  const name = decodeSafe((line.split("#")[1] || guessName(line, scheme)).trim());
  return {
    id: uid("node"),
    name,
    host: guessHost(line),
    port: guessPort(line),
    protocol: scheme,
    note: buildTags(name, scheme, line).join(" / "),
    region: guessRegion(name),
    raw: line
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

function applyTemplate(template) {
  const existing = new Set(state.strategies.map((item) => item.name));
  template.strategies.forEach((strategy) => {
    if (existing.has(strategy.name)) return;
    state.strategies.push({
      id: uid("strategy"),
      name: strategy.name,
      type: strategy.type,
      members: strategy.members.map((member) => ({ ...member }))
    });
  });
}

function ensureStrategyExists(name) {
  if (!name || allowedConstants.includes(name)) return;
  if (state.strategies.some((item) => item.name === name)) return;
  state.strategies.push({
    id: uid("strategy"),
    name,
    type: "select",
    members: [{ kind: "constant", value: "DIRECT" }]
  });
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
      rules.push({ id: uid("rule"), type, value, target });
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
      raw: proxy.raw || ""
    });
  });
  return Array.from(assetMap.values());
}

function importProxyGroups(lines) {
  const drafts = [];
  let current = null;
  let inProxies = false;

  lines.forEach((rawLine) => {
    const line = rawLine.trim();
    if (!line) return;
    if (line.startsWith("- name:")) {
      if (current) drafts.push(current);
      current = {
        id: uid("strategy"),
        name: line.split(":").slice(1).join(":").trim().replace(/^["']|["']$/g, ""),
        type: "select",
        proxyNames: []
      };
      inProxies = false;
      return;
    }
    if (!current) return;
    if (line.startsWith("type:")) {
      current.type = line.split(":").slice(1).join(":").trim();
      return;
    }
    if (line === "proxies:") {
      inProxies = true;
      return;
    }
    if (inProxies && line.startsWith("- ")) {
      current.proxyNames.push(line.slice(2).trim().replace(/^["']|["']$/g, ""));
    }
  });

  if (current) drafts.push(current);
  if (!drafts.length) return;

  const strategyNames = new Set(drafts.map((item) => item.name));
  const nodeNames = new Set(state.assets.flatMap((asset) => asset.nodes.map((node) => node.name)));

  state.strategies = drafts.map((draft) => ({
    id: draft.id,
    name: draft.name,
    type: draft.type,
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
      rules.push({ id: uid("rule"), type, value, target });
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
  state.strategies = Array.isArray(snapshot.state.strategies) ? snapshot.state.strategies : [];
  state.clashBaseRaw = snapshot.state.clashBaseRaw || defaultClashBaseRaw;
  state.rulesConfig = {
    snifferRaw: snapshot.state.rulesConfig?.snifferRaw || defaultSnifferRaw,
    providersRaw: snapshot.state.rulesConfig?.providersRaw || defaultProvidersRaw,
    rules: Array.isArray(snapshot.state.rulesConfig?.rules) ? snapshot.state.rulesConfig.rules : []
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
  const parsed = parseNodeLine(raw);
  asset.nodes.push(parsed);
  closeNodeModal();
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
  const result = buildOutputModel();
  const content = formatClash(result);
  const rawName = els.configExportName.value.trim();
  const baseName = rawName || nextVersionName();
  const finalName = /\.(yaml|yml|txt)$/i.test(baseName) ? baseName : `${baseName}.yaml`;
  if (window.desktopAPI?.saveConfigFile) {
    const targetPath = getPreferredSavePath(finalName);
    const saved = await window.desktopAPI.saveConfigFile({ filePath: targetPath, content });
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
      state.rulesConfig.rules = Array.isArray(data.rulesConfig.rules) ? data.rulesConfig.rules : [];
    }
    if (Array.isArray(data.strategies)) {
      state.strategies = data.strategies.map((strategy) => ({
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
  els.loadSampleBtn.addEventListener("click", () => { els.rawInput.value = sampleRawInput; });
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
  els.normalizeBtn.addEventListener("click", () => { state.nodes = normalizeRawInput(els.rawInput.value); seedAssetsFromNodes(); render(); });
  els.exportTemplateBtn.addEventListener("click", exportTemplateDb);
  els.seedAssetsBtn.addEventListener("click", () => { if (!state.nodes.length) state.nodes = normalizeRawInput(els.rawInput.value); seedAssetsFromNodes(); render(); });
  els.addAssetBtn.addEventListener("click", () => { state.assets.push({ id: uid("asset"), name: "新资产库", kind: "custom", nodes: [] }); render(); });
  els.addStrategyBtn.addEventListener("click", () => { state.strategies.push({ id: uid("strategy"), name: "新策略层", type: "select", members: [{ kind: "constant", value: "DIRECT" }] }); render(); });
  els.loadTemplateBtn.addEventListener("click", () => { applyTemplate(templates.basic); render(); });
  els.addProviderBtn.addEventListener("click", () => {
    state.rulesConfig.providersRaw = `${state.rulesConfig.providersRaw}\n\nNewProvider:\n  type: http\n  behavior: classical\n  path: ./ruleset/NewProvider.yaml\n  url: ""\n  interval: 86400`.trim();
    renderRules();
    renderOutput();
  });
  els.addRuleBtn.addEventListener("click", () => { state.rulesConfig.rules.push(emptyRule()); ensureStrategyExists("节点选择"); renderRules(); renderOutput(); });
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
    card.querySelector(".asset-name").addEventListener("input", (event) => { asset.name = event.target.value.trim() || "未命名资产库"; render(); });
    card.querySelector(".asset-kind").addEventListener("change", (event) => { asset.kind = event.target.value; renderOutput(); });
    card.querySelector(".asset-add-node").addEventListener("click", () => openNodeModal(asset.id));
    card.querySelector(".asset-delete").addEventListener("click", () => { state.assets = state.assets.filter((item) => item.id !== asset.id); render(); });

    const nodeList = card.querySelector(".asset-node-list");
    asset.nodes.forEach((node) => {
      const row = els.assetNodeTemplate.content.firstElementChild.cloneNode(true);
      row.querySelector(".node-name").value = node.name;
      row.querySelector(".node-host").value = node.host;
      row.querySelector(".node-port").value = node.port;
      row.querySelector(".node-protocol").value = node.protocol.toUpperCase();
      row.querySelector(".node-note").value = node.note;
      row.querySelector(".node-name").addEventListener("input", (event) => { node.name = event.target.value; renderOutput(); });
      row.querySelector(".node-host").addEventListener("input", (event) => { node.host = event.target.value; renderOutput(); });
      row.querySelector(".node-port").addEventListener("input", (event) => { node.port = event.target.value; renderOutput(); });
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

function renderSnifferSummary() {
  els.snifferSummary.innerHTML = "";
  const card = document.createElement("div");
  card.className = "summary-card";
  card.innerHTML = `<pre>${escapeHtml(state.rulesConfig.snifferRaw || "-")}</pre>`;
  els.snifferSummary.appendChild(card);
}

function renderSnifferEditor() {
  els.snifferEditor.innerHTML = "";
  const area = document.createElement("textarea");
  area.value = state.rulesConfig.snifferRaw;
  area.addEventListener("input", (event) => {
    state.rulesConfig.snifferRaw = event.target.value;
    renderSnifferSummary();
    renderOutput();
  });
  const card = document.createElement("div");
  card.className = "summary-card";
  card.appendChild(area);
  els.snifferEditor.appendChild(card);
}

function renderProvidersSummary() {
  els.providersSummary.innerHTML = "";
  const card = document.createElement("div");
  card.className = "summary-card";
  card.innerHTML = `<pre>${escapeHtml(state.rulesConfig.providersRaw || "-")}</pre>`;
  els.providersSummary.appendChild(card);
}

function renderProvidersEditor() {
  els.providersEditor.innerHTML = "";
  const area = document.createElement("textarea");
  area.value = state.rulesConfig.providersRaw;
  area.addEventListener("input", (event) => {
    state.rulesConfig.providersRaw = event.target.value;
    renderProvidersSummary();
    renderOutput();
  });
  const card = document.createElement("div");
  card.className = "summary-card";
  card.appendChild(area);
  els.providersEditor.appendChild(card);
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
    type: strategy.type,
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
  const lines = [
    state.clashBaseRaw,
    "",
    "sniffer:",
    ...indentBlock(state.rulesConfig.snifferRaw),
    "",
    "rule-providers:",
    ...indentBlock(state.rulesConfig.providersRaw)
  ];
  lines.push("", "proxies:");
  state.assets.forEach((asset) => {
    asset.nodes.forEach((node) => {
      const fields = [
        `name: ${node.name}`,
        `server: ${node.host || "test.test"}`,
        `port: ${node.port || "443"}`,
        `type: ${node.protocol || "ss"}`
      ];
      lines.push(`  - {${fields.join(", ")}}`);
    });
  });
  lines.push("", "proxy-groups:");
  result.groups.forEach((group) => {
    lines.push(`  - name: ${yamlString(group.name)}`);
    lines.push(`    type: ${group.type}`);
    if (group.type === "url-test") {
      lines.push("    url: http://www.gstatic.com/generate_204");
      lines.push("    interval: 600");
    }
    lines.push("    proxies:");
    group.proxies.forEach((proxy) => lines.push(`      - ${yamlString(proxy)}`));
  });
  lines.push("", "rules:");
  state.rulesConfig.rules.forEach((rule) => {
    lines.push(`  - ${[rule.type, rule.value, rule.target].filter(Boolean).join(",")}`);
  });
  return lines.join("\n");
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

function formatOutput(result) {
  return els.targetFormat.value === "surge" ? formatSurge(result) : formatClash(result);
}

function renderOutput() {
  const result = buildOutputModel();
  els.resolveInfo.textContent = `已解析 ${result.totalResolvedNodes} 个叶子节点，${result.reusedStrategies} 个策略引用，${state.rulesConfig.rules.length} 条规则`;
  renderValidation(result.errors);
  els.outputPreview.textContent = formatOutput(result);
  schedulePersist();
}

function render() {
  renderAssets();
  renderStrategies();
  renderRules();
  renderStats();
  renderOutput();
}

function yamlString(value) {
  return /[\s:[\]#]/.test(value) ? `"${String(value).replace(/"/g, '\\"')}"` : String(value);
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

async function boot() {
  bindEvents();

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
