import "./styles.css";
import JSZip from "jszip";

const SCORE_BY_SEVERITY = { critical: 35, high: 20, medium: 10, low: 4 };
const DOCUMENT_EXTENSIONS = new Set(["md", "txt", "rst", "adoc", "json", "yaml", "yml", "toml", "ini", "cfg", "lock"]);
const SCRIPT_EXTENSIONS = new Set(["py", "js", "mjs", "cjs", "sh", "bash", "zsh"]);
const SHEBANG_PATTERN = /^#!.*\b(bash|sh|zsh|python|node)\b/m;
const TEXT_BINARY_THRESHOLD = 0.3;

const RULES = [
  createRule("identity-collection", "Identity collection", "medium", "Collects usernames, hostnames, or machine identity.", [/\bos\.getlogin\s*\(/, /\bgetpass\.getuser\s*\(/, /\bplatform\.node\s*\(/, /\bos\.hostname\s*\(/, /\bprocess\.env\.USERNAME\b/i, /\bwhoami\b/, /\bhostname\b/]),
  createRule("env-access", "Environment variable access", "high", "Reads environment variables that may expose secrets.", [/\bos\.environ\b/, /\bos\.getenv\s*\(/, /\bprocess\.env\b/, /\bprintenv\b/, /\benv\b/]),
  createRule("command-exec", "System command execution", "critical", "Executes local commands or spawns child processes.", [/\bos\.system\s*\(/, /\bsubprocess\.(Popen|call|run|check_output)\s*\(/, /\bchild_process\.(exec|execSync|spawn|spawnSync|fork)\s*\(/, /\bexec\s*\(/, /\bpopen\s+/i, /\bnohup\b/]),
  createRule("dynamic-exec", "Dynamic code execution", "critical", "Evaluates generated code dynamically.", [/\beval\s*\(/, /\bexec\s*\(/, /\bFunction\s*\(/, /\bsetTimeout\s*\(\s*["'`]/, /\bsetInterval\s*\(\s*["'`]/, /\b__import__\s*\(/]),
  createRule("file-access", "File system access", "medium", "Reads or writes local files or traverses directories.", [/\bopen\s*\([^)]*['"][rwa]/, /\bpathlib\.Path\b/, /\bfs\.(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\b/, /\bcat\s+\//, /\bls\s+/, /\bfind\s+\//]),
  createRule("network-exfil", "Network or exfiltration", "critical", "Sends requests or opens sockets to external systems.", [/\brequests\.(get|post|put|delete|request)\s*\(/, /\burllib\.request\b/, /\bsocket\b/, /\bfetch\s*\(/, /\bXMLHttpRequest\b/, /\baxios\.(get|post|put|delete|request)\b/, /\bcurl\b/, /\bwget\b/, /\bnc\s+/]),
  createRule("sensitive-harvest", "Sensitive data targeting", "high", "Looks for credentials, cookies, tokens, or private contact data.", [/\bcookie\b/i, /\bpassword\b/i, /\btoken\b/i, /\bapi[_-]?key\b/i, /\bsecret\b/i, /\bemail\b/i, /手机号/]),
  createRule("dynamic-import", "Dynamic module loading", "medium", "Loads modules dynamically to hide behavior.", [/\bimportlib\.import_module\s*\(/, /\b__import__\s*\(/, /\brequire\s*\(\s*[^"'`]/, /\bimport\s*\(\s*[^"'`]/]),
  createRule("dangerous-libs", "Dangerous system libraries", "medium", "Uses low-level libraries often involved in host control.", [/\bctypes\b/, /\bsubprocess\b/, /\bsocket\b/, /\bos\b/, /\bchild_process\b/, /\bprocess\b/]),
  createRule("system-mutation", "System mutation", "high", "Deletes files, changes permissions, or mutates local system state.", [/\bos\.chmod\s*\(/, /\bos\.remove\s*\(/, /\bshutil\.rmtree\s*\(/, /\brm\s+-rf\b/, /\bchmod\s+\+x\b/, /\bmv\s+/, /\bdel\s+/i]),
  createRule("obfuscation", "Obfuscation or encoded payloads", "high", "Uses encoded or serialized payload techniques.", [/\bbase64\b/, /\bbinascii\b/, /\bmarshal\b/, /\batob\s*\(/, /\bBuffer\.from\s*\([^)]*base64/i, /\bzlib\b/]),
  createRule("background-exec", "Background execution", "medium", "Starts background tasks or hides long-running work.", [/\bthreading\.Thread\s*\(/, /\bmultiprocessing\b/, /\bdaemon\s*=\s*True\b/, /&\s*$/, /\bstart\s+\/b\b/i, /\bsetsid\b/]),
  createRule("download-exec", "Download and execute chain", "critical", "Downloads remote content and executes it locally.", [/\bcurl\b.*\|\s*(sh|bash|zsh)/, /\bwget\b.*\|\s*(sh|bash|zsh)/, /\bInvoke-WebRequest\b.*iex/i, /\brequests\.get\b.*\bexec\b/s]),
  createRule("credential-targeting", "Credential file targeting", "high", "Directly references known secret or credential paths.", [/\.env\b/, /\.ssh\b/, /\.npmrc\b/, /id_rsa\b/, /known_hosts\b/, /Cookies\b/i, /keychain\b/i]),
  createRule("autorun-hooks", "Auto-run install hooks", "medium", "Uses install or bootstrap files that may run on setup.", [/\bpostinstall\b/i, /\bpreinstall\b/i, /\bbootstrap\b/i, /\bsetup\.py\b/i, /\binstall\.sh\b/i, /\bentrypoint\b/i]),
];

const COMBO_RULES = [
  { id: "exec-plus-network", labels: ["command-exec", "network-exfil"], penalty: 15, message: "Combines command execution with outbound network behavior." },
  { id: "env-plus-network", labels: ["env-access", "network-exfil"], penalty: 15, message: "Reads environment secrets and also performs network activity." },
  { id: "dynamic-plus-obfuscated", labels: ["dynamic-exec", "obfuscation"], penalty: 15, message: "Mixes dynamic execution with encoded payload techniques." },
  { id: "mutation-plus-background", labels: ["system-mutation", "background-exec"], penalty: 10, message: "Changes the system and also schedules hidden/background execution." },
];

const app = document.querySelector("#app");
const state = { phase: "idle", progress: { current: 0, total: 0, label: "Waiting for a ZIP file." }, result: null };

render();

function createRule(id, label, severity, description, patterns) {
  return { id, label, severity, description, scoreImpact: SCORE_BY_SEVERITY[severity], patterns };
}

function render() {
  app.innerHTML = `
    <div class="page-shell">
      <div class="ambient ambient-a"></div>
      <div class="ambient ambient-b"></div>
      <header class="hero">
        <div class="hero-copy">
          <p class="eyebrow">SkillScope / local trust review</p>
          <h1>Scan community skill bundles before they scan you.</h1>
          <p class="hero-lead">Skills can hide Python, JavaScript, or shell automation with very little visibility. SkillScope exists because that safety gap is real. Drop a ZIP package here and inspect it locally, entirely in your browser.</p>
          <div class="hero-points"><span>No backend uploads</span><span>Recursive ZIP traversal</span><span>100-point safety score</span></div>
        </div>
        <aside class="hero-panel">
          <div class="hero-panel-grid"></div>
          <p class="panel-label">Local processing only</p>
          <p class="panel-title">Nothing leaves your machine.</p>
          <p class="panel-copy">This website does not upload your files to any server. Extraction and scanning happen entirely in your browser.</p>
        </aside>
      </header>
      <main class="content">
        <section class="upload-section">
          <div class="section-head"><p class="section-kicker">Upload</p><h2>Inspect one ZIP package at a time.</h2></div>
          <label class="dropzone ${state.phase === "scanning" ? "is-busy" : ""}" for="zip-upload">
            <input id="zip-upload" type="file" accept=".zip,application/zip" ${state.phase === "scanning" ? "disabled" : ""} />
            <span class="dropzone-title">Drop a skill ZIP here or click to browse</span>
            <span class="dropzone-subtitle">Single archive only. No files are uploaded or stored.</span>
          </label>
          <div class="trust-strip">
            <p>This project exists because community skills often ship without a transparent safety review.</p>
            <p>Your archive is decompressed, parsed, and scored in this tab only.</p>
          </div>
        </section>
        <section class="progress-section">
          <div class="section-head"><p class="section-kicker">Progress</p><h2>Local scan status</h2></div>
          <div class="progress-card">
            <div class="progress-meta"><p>${escapeHtml(state.progress.label)}</p><span>${state.progress.current} / ${state.progress.total}</span></div>
            <div class="progress-bar"><span style="width:${computeProgressWidth()}%"></span></div>
          </div>
        </section>
        ${renderResults()}
        <section class="limitations">
          <div class="section-head"><p class="section-kicker">Limitations</p><h2>Heuristic, not execution-based</h2></div>
          <div class="limitations-grid">
            <p>SkillScope uses static keyword and pattern analysis. It does not execute code or emulate a sandbox.</p>
            <p>Some files will be flagged conservatively to surface suspicious behavior early. Manual review still matters.</p>
            <p>Archives containing only markdown or documentation files are treated as low risk and receive a full score.</p>
          </div>
        </section>
      </main>
    </div>`;

  document.querySelector("#zip-upload")?.addEventListener("change", handleUpload);
}

function renderResults() {
  if (!state.result) {
    return `<section class="summary-section placeholder"><div class="section-head"><p class="section-kicker">Verdict</p><h2>Awaiting a package</h2></div><p class="placeholder-copy">Upload a ZIP to generate a score, a verdict, and a file-by-file risk breakdown.</p></section>`;
  }

  const { archiveSummary, files, overallScore, overallSeverity, verdictLabel } = state.result;
  return `
    <section class="summary-section">
      <div class="section-head"><p class="section-kicker">Verdict</p><h2>${escapeHtml(verdictLabel)}</h2></div>
      <div class="summary-grid severity-${overallSeverity}">
        <div class="score-tile">
          <div class="score-head">
            <p class="score-label">Overall score</p>
            <span class="score-chip">${escapeHtml(verdictLabel)}</span>
          </div>
          <div class="score-display">
            <p class="score-value">${overallScore}</p>
            <p class="score-scale">/100</p>
          </div>
        </div>
        <div class="summary-stats">
          <div><span>Files scanned</span><strong>${archiveSummary.totalFiles}</strong></div>
          <div><span>Script files</span><strong>${archiveSummary.scriptFiles}</strong></div>
          <div><span>High risk</span><strong>${archiveSummary.high}</strong></div>
          <div><span>Medium risk</span><strong>${archiveSummary.medium}</strong></div>
          <div><span>Low risk</span><strong>${archiveSummary.low}</strong></div>
        </div>
      </div>
    </section>
    <section class="findings-section">
      <div class="section-head"><p class="section-kicker">Per file</p><h2>Evidence and deductions</h2></div>
      <div class="findings-list">
        ${files.map((file) => `
          <details class="finding-row severity-${file.severity}" ${file.severity !== "low" ? "open" : ""}>
            <summary>
              <div><p class="finding-path">${escapeHtml(file.path)}</p><p class="finding-meta">${file.type.toUpperCase()} • ${formatBytes(file.size)} • ${file.isScript ? "script" : "doc / data"}</p></div>
              <div class="finding-side"><span class="badge">${formatSeverity(file.severity)}</span><span class="file-score">${file.score}/100</span></div>
            </summary>
            <div class="finding-body">
              ${file.matches.length ? `<ul class="finding-tags">${file.matches.map((match) => `<li><strong>${escapeHtml(match.label)}</strong><span>${escapeHtml(match.description)}</span><code>${escapeHtml(match.evidence)}</code></li>`).join("")}</ul>` : `<p class="clean-note">No suspicious patterns matched in this file.</p>`}
              ${file.deductions.length ? `<div class="deductions">${file.deductions.map((entry) => `<p><span>${escapeHtml(entry.reason)}</span><strong>-${entry.penalty}</strong></p>`).join("")}</div>` : ""}
            </div>
          </details>`).join("")}
      </div>
    </section>`;
}

function computeProgressWidth() {
  return state.progress.total ? Math.min(100, Math.round((state.progress.current / state.progress.total) * 100)) : 0;
}

async function handleUpload(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  state.phase = "scanning";
  state.result = null;
  state.progress = { current: 0, total: 1, label: "Reading ZIP archive..." };
  render();

  try {
    const zip = await JSZip.loadAsync(await file.arrayBuffer());
    const entries = Object.values(zip.files).filter((entry) => !entry.dir);
    state.progress = { current: 0, total: Math.max(entries.length, 1), label: "Inspecting archive contents..." };
    render();

    const scannedFiles = [];
    for (const [index, entry] of entries.entries()) {
      scannedFiles.push(await scanZipEntry(entry));
      state.progress = { current: index + 1, total: entries.length, label: `Scanning ${entry.name}` };
      render();
      await pauseFrame();
    }

    state.result = summarizeResults(scannedFiles);
    state.phase = "done";
    state.progress = { current: entries.length, total: entries.length, label: "Local scan completed." };
  } catch (error) {
    state.phase = "error";
    state.progress = { current: 0, total: 1, label: `Unable to scan archive: ${error.message}` };
  }

  render();
  document.querySelector("#zip-upload").value = "";
}

async function scanZipEntry(entry) {
  const path = entry.name;
  const extension = path.includes(".") ? path.split(".").pop().toLowerCase() : "";
  const bytes = await entry.async("uint8array");
  const size = bytes.byteLength;
  if (!isTextBuffer(bytes)) {
    return { path, type: extension || "binary", size, isScript: false, severity: "low", score: 100, deductions: [], matches: [] };
  }

  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  const isScript = isScriptFile(path, extension, text);
  if (!isScript) {
    return { path, type: extension || "text", size, isScript: false, severity: "low", score: 100, deductions: [], matches: [] };
  }

  return scoreScriptFile(path, extension || "script", size, text);
}

function scoreScriptFile(path, type, size, text) {
  const matches = [];
  const deductions = [];
  const triggered = new Set();

  for (const rule of RULES) {
    const evidence = findEvidence(rule.patterns, text);
    if (!evidence) continue;
    triggered.add(rule.id);
    matches.push({ ruleId: rule.id, label: rule.label, severity: rule.severity, description: rule.description, evidence, lineNumber: findLineNumber(text, evidence), scoreImpact: rule.scoreImpact });
    deductions.push({ reason: `${rule.label} (${formatSeverity(rule.severity)})`, penalty: rule.scoreImpact });
  }

  for (const combo of COMBO_RULES) {
    if (combo.labels.every((label) => triggered.has(label))) deductions.push({ reason: combo.message, penalty: combo.penalty });
  }

  const filePenalty = Math.min(50, deductions.reduce((sum, item) => sum + item.penalty, 0));
  const computedScore = Math.max(0, 100 - filePenalty);
  const score = matches.length === 0 ? 98 : computedScore;
  return { path, type, size, isScript: true, severity: deriveSeverity(matches, score), score, deductions: matches.length === 0 ? [] : deductions, matches };
}

function summarizeResults(files) {
  const hasScripts = files.some((file) => file.isScript);
  const docsOnly = files.length > 0 && files.every((file) => !file.isScript);
  if (docsOnly || !hasScripts) {
    return { files: sortFiles(files), findings: [], overallScore: 100, overallSeverity: "low", verdictLabel: "Clean documentation bundle", archiveSummary: buildSummary(files, 100, "low") };
  }

  const totalPenalty = files.reduce((sum, file) => sum + (100 - file.score), 0);
  const overallScore = Math.max(0, 100 - totalPenalty);
  const overallSeverity = mapScoreToSeverity(overallScore);
  return { files: sortFiles(files), findings: files.flatMap((file) => file.matches), overallScore, overallSeverity, verdictLabel: scoreToVerdict(overallScore), archiveSummary: buildSummary(files, overallScore, overallSeverity) };
}

function buildSummary(files, overallScore, overallSeverity) {
  return {
    totalFiles: files.length,
    scriptFiles: files.filter((file) => file.isScript).length,
    high: files.filter((file) => file.severity === "high" || file.severity === "critical").length,
    medium: files.filter((file) => file.severity === "medium").length,
    low: files.filter((file) => file.severity === "low").length,
    overallScore,
    overallSeverity,
  };
}

function mapScoreToSeverity(score) {
  if (score >= 90) return "low";
  if (score >= 70) return "medium";
  if (score >= 40) return "high";
  return "critical";
}

function scoreToVerdict(score) {
  if (score >= 90) return "Clean";
  if (score >= 70) return "Guarded";
  if (score >= 40) return "High concern";
  return "Critical";
}

function deriveSeverity(matches, score) {
  if (matches.some((item) => item.severity === "critical")) return "critical";
  if (matches.some((item) => item.severity === "high")) return score < 40 ? "critical" : "high";
  if (matches.some((item) => item.severity === "medium")) return "medium";
  return "low";
}

function findEvidence(patterns, text) {
  for (const pattern of patterns) {
    pattern.lastIndex = 0;
    const match = text.match(pattern);
    if (match?.[0]) return match[0].slice(0, 140);
  }
  return "";
}

function findLineNumber(text, evidence) {
  const index = text.indexOf(evidence);
  return index < 0 ? null : text.slice(0, index).split("\n").length;
}

function isScriptFile(path, extension, text) {
  if (SCRIPT_EXTENSIONS.has(extension)) return true;
  const fileName = path.split("/").pop()?.toLowerCase() || "";
  if (["install", "setup", "run", "bootstrap", "entrypoint"].includes(fileName)) return SHEBANG_PATTERN.test(text);
  return SHEBANG_PATTERN.test(text);
}

function isTextBuffer(bytes) {
  let suspicious = 0;
  const sample = bytes.subarray(0, Math.min(bytes.length, 1024));
  for (const value of sample) {
    if (value === 0) return false;
    if (value < 7 || (value > 14 && value < 32)) suspicious += 1;
  }
  return sample.length === 0 || suspicious / sample.length < TEXT_BINARY_THRESHOLD;
}

function sortFiles(files) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...files].sort((a, b) => order[a.severity] - order[b.severity] || a.path.localeCompare(b.path));
}

function formatSeverity(severity) {
  if (severity === "critical") return "Critical";
  if (severity === "high") return "High";
  if (severity === "medium") return "Guarded";
  return "Low";
}

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
}

function escapeHtml(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function pauseFrame() {
  return new Promise((resolve) => requestAnimationFrame(() => resolve()));
}
