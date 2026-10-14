
"use strict";

/* ScamShield+ - browser-only demo. OCR needs internet on first use. */
const HISTORY_KEY = "scamshield_history_v3";
const MAX_HISTORY = 300;
let scans = loadHistory(), lastScan = null, bulkResults = [];

const samples = {
  scam: "URGENT! Congratulations! You won Rs. 50,000. Click this link immediately to claim your prize. Verify your bank account and share your OTP. Your account will be blocked today.",
  safe: "Hello team, our project review meeting is scheduled for tomorrow at 10 AM. Please bring the updated slides and notes. Thank you.",
  link: "Your bank account will be suspended today. Click this link immediately to verify your password: http://secure-account-verify.example.invalid/login"
};

function loadHistory() {
  try {
    const x = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    return Array.isArray(x) ? x : [];
  } catch (_) {
    return [];
  }
}

function saveHistory() {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(scans.slice(0, MAX_HISTORY)));
  } catch (e) {
    console.warn(e);
    toast("Browser storage is full; this history may not persist.");
  }
}

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;"
  })[c]);
}

function norm(s) {
  return String(s).toLowerCase().replace(/[^a-z0-9₹$]+/g, " ").trim();
}

function languageOf(s) {
  if (/[\u0C00-\u0C7F]/.test(s) && /[a-z]/i.test(s)) return "Telugu + English";
  if (/[\u0C00-\u0C7F]/.test(s)) return "Telugu";
  if (/\b(cheyandi|cheyyandi|pampandi|ivvandi|avutundi|mee|dabbu|bahumathi|geluchukunnaru|kattandi|ventane|otp pampandi)\b/i.test(s)) return "Telugu transliteration / English";
  return "English / other";
}

function level(score) {
  return score >= 50 ? "High" : score >= 20 ? "Medium" : "Low";
}

const rules = [
  {
    cat: "Credential theft",
    name: "OTP, password or PIN request",
    pts: 35,
    re: /\b(otp|one time password|password|passcode|pin|cvv|cvc|security code|recovery code|login credentials)\b/i,
    act: /\b(share|send|provide|enter|confirm|reply|tell|submit|give|update|verify|reveal|type|fill|request|required|upload)\b/i,
    te: /ఓటీపీ|ఓటిపి|పాస్‌వర్డ్|పాస్ వర్డ్|సెక్యూరిటీ కోడ్/,
    tea: /షేర్|పంపండి|చెప్పండి|ఇవ్వండి|నమోదు చేయండి|ఎంటర్ చేయండి|వెరిఫై|నిర్ధారించండి/,
    tr: /\b(otp pampandi|otp share cheyandi|password pampandi|pin ivvandi|bank details ivvandi)\b/i,
    detail: "The message may request sensitive login or payment credentials."
  },
  {
    cat: "Urgency / threats",
    name: "Urgent threat or account blocking",
    pts: 20,
    re: /\b(urgent|immediately|act now|final warning|last chance|account blocked|account suspended|account frozen|account will be blocked|account will be suspended|expires today|within \d+ hours|legal action|avoid closure|respond now|limited time)\b/i,
    te: /వెంటనే|తక్షణమే|ఖాతా.{0,25}(బ్లాక్|నిలిపి|మూసి)|చివరి హెచ్చరిక|ఈరోజే/,
    tr: /\b(ventane|mee account block avutundi|mee bank account block|account block avutundi|account block avuthundi|twaraga cheyandi)\b/i,
    detail: "Urgency or threats can pressure people into acting before verifying."
  },
  {
    cat: "Prize / reward",
    name: "Prize or unexpected reward",
    pts: 25,
    re: /\b(congratulation|congratulations|congrats|you have won|you won|you win|winner|free prize|lottery|lucky draw|giveaway|gift voucher|cash prize|reward money|prize money)\b/i,
    te: /అభినందనలు|బహుమతి|లాటరీ|గెలుచుకున్నారు|గెలిచారు|విజేత|ఉచిత బహుమతి/,
    tr: /\b(congratulations?|congrats|bahumathi|bahumati|geluchukunnaru|gelicharu|prize vachindi)\b/i,
    detail: "Unexpected winnings and rewards are common scam lures."
  },
  {
    cat: "Money claim",
    name: "Claim money or a reward",
    pts: 25,
    re: /\b(claim the money|claim money|claim your money|claim the prize|claim your prize|claim the reward|claim your reward|collect your money|receive your reward|collect the cash|get your bonus)\b/i,
    te: /డబ్బు.{0,25}(పొందండి|తీసుకోండి|క్లెయిమ్|వసూలు)|బహుమతి.{0,25}(పొందండి|తీసుకోండి)/,
    tr: /\b(claim the money|dabbu pondandi|dabbu teesukondi|bahumathi pondandi|reward claim cheyandi)\b/i,
    detail: "The message urges the recipient to claim money or a reward."
  },
  {
    cat: "Suspicious link instruction",
    name: "Click or verify instruction",
    pts: 15,
    re: /\b(click\s+(the\s+)?(link|url|here|below|this)|tap here|link below|click below|open this link|verify your account|verify immediately|update your account|confirm your details|login now|sign in immediately|kyc update)\b/i,
    te: /లింక్.{0,25}(క్లిక్|ఓపెన్)|క్లిక్ చేయండి|లింక్ పై క్లిక్|ఇక్కడ క్లిక్|వెరిఫై చేయండి|నిర్ధారించండి/,
    tr: /\b(link click cheyandi|click cheyandi|link open cheyandi|ikkada click cheyandi|ventane verify cheyandi|kyc update cheyandi)\b/i,
    detail: "The message encourages clicking a link or verifying details through an instruction."
  },
  {
    cat: "Payment / fee",
    name: "Payment or advance fee request",
    pts: 25,
    re: /\b(registration fee|processing fee|refundable fee|advance fee|security deposit|pay now|send money|transfer money|payment required|pay a fee|claim fee|delivery fee|redelivery fee|customs fee|joining fee|interview fee|gift cards?|upi payment|bank transfer|deposit now|pay the fee|pay penalty)\b/i,
    te: /ఫీజు|రుసుము|డబ్బు చెల్లించండి|చెల్లింపు చేయండి|నమోదు రుసుము|ముందుగా డబ్బు|పెనాల్టీ చెల్లించండి/,
    tr: /\b(registration fee kattandi|fee pay cheyandi|dabbu pampandi|payment cheyandi|munduga dabbu|fee kattandi)\b/i,
    detail: "A payment, fee or money transfer is mentioned."
  },
  {
    cat: "Personal / banking data",
    name: "Banking or identity information",
    pts: 25,
    re: /\b(aadhaar|aadhar|pan card|bank details|account number|card details|debit card|credit card|identity proof|date of birth|upi id|banking information|personal information)\b/i,
    act: /\b(share|send|provide|enter|upload|confirm|verify|update|submit|reply|give|fill|click|required|request)\b/i,
    te: /ఆధార్|పాన్ కార్డు|బ్యాంక్ వివరాలు|ఖాతా నంబర్|కార్డు వివరాలు|వ్యక్తిగత సమాచారం/,
    tea: /షేర్|పంపండి|ఇవ్వండి|నమోదు చేయండి|అప్‌డేట్|వెరిఫై|నిర్ధారించండి/,
    tr: /\b(aadhaar details share cheyandi|bank details ivvandi|account number pampandi|card details ivvandi)\b/i,
    detail: "Sensitive banking or identity details may be requested."
  },
  {
    cat: "Job / earning offer",
    name: "Suspicious job or earning offer",
    pts: 20,
    re: /\b(work from home|work from anywhere|daily income|guaranteed income|selected for the job|no experience required|part time job|job offer|job opportunity|earn rs|joining fee|job registration|earn \$?\d+ daily)\b/i,
    te: /ఉద్యోగం|ఇంటి నుంచే పని|రోజుకు ఆదాయం|జీతం|నమోదు ఫీజు/,
    tr: /\b(job offer|work from home|daily income|job kosam fee|job registration fee)\b/i,
    detail: "This may be a job lure or unusually attractive earning offer."
  },
  {
    cat: "Delivery / refund",
    name: "Delivery or refund warning",
    pts: 15,
    re: /\b(delivery failed|redelivery fee|parcel held|package held|refund pending|refund failed|customs fee|courier fee|delivery address incomplete|shipment blocked)\b/i,
    detail: "Delivery and refund messages can be used to solicit fees or card details."
  },
  {
    cat: "Impersonation",
    name: "Possible organization impersonation",
    pts: 15,
    re: /\b(dear customer|dear user|bank support|security team|customer care|government grant|technical support|your bank|account department|police department|email administrator)\b/i,
    act: /\b(urgent|verify|blocked|suspended|click|payment|install|password|details|otp|kyc|fee|update|confirm|disable|immediately)\b/i,
    detail: "The message may be imitating an organization or support team."
  },
  {
    cat: "Remote access",
    name: "Remote access or suspicious installation",
    pts: 25,
    re: /\b(remote access|anydesk|teamviewer|install this app|download this app|screen sharing|computer is infected|device is infected|virus detected|call this support number)\b/i,
    detail: "Unsolicited remote access requests or app installations can expose a device."
  },
  {
    cat: "Intimidation",
    name: "Threats or intimidation",
    pts: 20,
    re: /\b(arrest warrant|arrest|police case|court case|legal action|fine will be imposed|service will be disconnected|pay penalty)\b/i,
    detail: "Threats of legal trouble or penalties can be used to intimidate recipients."
  },
  {
    cat: "Telugu wording",
    name: "Telugu scam-related wording",
    pts: 10,
    te: /ఓటీపీ|బహుమతి|డబ్బు|ఫీజు|ఖాతా బ్లాక్|లింక్ క్లిక్|వెంటనే చెల్లించండి/,
    tr: /\b(otp pampandi|dabbu pondandi|bahumathi|mee account block avutundi|link click cheyandi|ventane pay cheyandi)\b/i,
    detail: "A Telugu or Telugu-transliterated phrase was recognized; interpret it in context."
  }
];

function findUrls(text) {
  const re = /(?:https?:\/\/|www\.)[^\s<>"']+|(?:[a-z0-9-]+\.)+(?:com|net|org|in|io|co|gov|edu|app|site|xyz|info|biz|online|click|top|shop|dev|me|ly|invalid|test)(?:\/[^\s<>"']*)?/gi;
  return (String(text).match(re) || []).map(u => u.replace(/[),.!?;:'"\]]+$/g, ""));
}

const shorteners = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
  "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly", "buff.ly"
];

function inspectURL(raw) {
  let u, host = "";
  const fs = [];
  let score = 0;

  const add = (name, pts, detail) => {
    fs.push({ category: "URL safety", name, points: pts, detail });
    score += pts;
  };

  try {
    u = new URL(/^https?:\/\//i.test(raw) ? raw : "https://" + raw);
    host = u.hostname.toLowerCase();
    if (!host.includes(".")) throw Error();
  } catch (_) {
    return {
      score: 35, level: "Medium", hostname: host,
      findings: [{
        category: "URL safety", name: "Malformed URL", points: 35,
        detail: "This text could not be parsed as a normal URL."
      }]
    };
  }

  if (u.protocol !== "https:") add("HTTP instead of HTTPS", 15, "HTTP is not encrypted; this alone does not prove fraud.");
  if (shorteners.includes(host)) add("Shortened URL", 20, "A shortening service hides the final destination.");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add("Numeric IP address", 25, "The URL uses a numeric IP address.");
  if (host.split(".").some(p => p.startsWith("xn--"))) add("Punycode domain", 20, "Encoded domain characters may resemble other letters.");
  if (host.includes("--") || host.split(".").length >= 5) add("Unusual domain structure", 12, "The domain structure deserves closer inspection.");
  if (u.username || u.password) add("Credentials embedded in URL", 25, "The URL contains user information before its hostname.");
  if (/\.(invalid|test|local)$/i.test(host)) add("Reserved/test domain ending", 20, "This ending is normally reserved for testing or local use.");
  if (/\.(click|top|xyz|buzz|work|rest)$/i.test(host)) add("Domain ending worth checking", 8, "A domain ending alone is not proof of fraud.");
  if (/\b(login|verify|claim|secure|account|wallet|password|banking|reward)\b/i.test(host)) add("Sensitive-action words in domain", 8, "The domain contains words often used in impersonation links.");
  if (host.length > 40) add("Unusually long domain", 8, "The domain is unusually long.");

  score = Math.min(100, score);
  if (fs.length >= 3) score = Math.max(score, 55);
  else if (fs.length === 2) score = Math.max(score, 30);
  score = Math.min(100, score);

  return { score, level: level(score), hostname: host, findings: fs };
}

function analyze(text) {
  const n = norm(text), findings = [], seen = new Set();

  for (const r of rules) {
    const en = !!(r.re && r.re.test(n) && (!r.act || r.act.test(n)));
    const tr = !!(r.tr && r.tr.test(n));
    const te = !!(r.te && r.te.test(text) && (!r.tea || r.tea.test(text)));

    if ((en || tr || te) && !seen.has(r.cat)) {
      findings.push({
        category: r.cat, name: r.name, points: r.pts,
        detail: r.detail || "This pattern deserves review."
      });
      seen.add(r.cat);
    }
  }

  const urls = findUrls(text);
  for (const url of urls) {
    for (const f of inspectURL(url).findings) {
      if (!findings.some(x => x.name === f.name)) findings.push(f);
    }
  }

  if (urls.length && !findings.some(f => f.name === "Link included")) {
    findings.push({
      category: "Link included", name: "Link included", points: 5,
      detail: "A link is present; a link alone does not prove fraud."
    });
  }

  let score = findings.reduce((s, f) => s + f.points, 0);
  const substantial = findings.filter(f => f.points >= 10).length;
  if (substantial >= 3) score = Math.max(score, 60);
  else if (substantial === 2) score = Math.max(score, 35);
  score = Math.min(100, score);

  return {
    score, level: level(score), findings, urls,
    language: languageOf(text)
  };
}

function advice(l) {
  if (l === "High") {
    return "High risk: Do not click links, pay money, install unknown apps, or share OTPs, passwords, PINs or bank details. Verify through an official app, website or phone number.";
  }
  if (l === "Medium") {
    return "Use caution. Check the sender and verify independently. Do not share personal information or pay fees until the request is confirmed.";
  }
  return "No strong warning patterns were detected. This does not prove the message is safe; verify the sender and links before acting.";
}

function toast(msg) {
  let el = document.getElementById("ssToast");
  if (!el) {
    el = document.createElement("div");
    el.id = "ssToast";
    el.setAttribute("role", "status");
    document.body.appendChild(el);
  }
  el.textContent = msg;
  el.classList.add("show");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => el.classList.remove("show"), 3000);
}

function err(msg) {
  const el = document.getElementById("errorMessage");
  if (el) {
    el.textContent = msg;
    el.hidden = false;
  } else alert(msg);
}

function clearErr() {
  const e = document.getElementById("errorMessage");
  if (e) {
    e.textContent = "";
    e.hidden = true;
  }
}

function itemFor(type, text, r) {
  return {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    type, content: text, score: r.score, level: r.level,
    findings: r.findings, advice: advice(r.level),
    language: r.language || languageOf(text),
    date: new Date().toISOString()
  };
}

function analyzeButton() {
  clearErr();
  const input = document.getElementById("messageInput");
  const text = input.value.trim();

  if (!text) {
    err("Please enter a message or URL before clicking Analyze.");
    input.focus();
    return;
  }

  const item = itemFor("Message", text, analyze(text));
  showResult(item);
  saveScan(item);
  toast("Analysis complete. Review the warning signs.");
}

function showResult(item) {
  lastScan = item;
  document.getElementById("emptyState").hidden = true;
  document.getElementById("resultSection").hidden = false;
  document.getElementById("riskScore").textContent = item.score;

  const badge = document.getElementById("riskBadge");
  badge.textContent = item.level + " Risk";
  badge.className = "risk-badge " + item.level.toLowerCase();

  document.getElementById("riskTitle").textContent =
    item.level === "High" ? "Potential Scam Detected" :
    item.level === "Medium" ? "Use Caution" : "No Strong Warning Signs";

  document.getElementById("riskDescription").textContent =
    item.level === "High" ? "Several warning signs need your attention." :
    item.level === "Medium" ? "Some warning signs were detected. Verify before responding." :
    "Few listed warning signs were detected. Remain cautious.";

  const bar = document.getElementById("scoreBar");
  bar.style.width = item.score + "%";
  bar.style.background = item.level === "High" ? "#e45462" :
    item.level === "Medium" ? "#e5a63b" : "#25bf92";

  const circle = document.getElementById("riskCircle");
  circle.style.setProperty("--risk-score", item.score + "%");
  circle.style.setProperty("--risk-color", bar.style.background);

  const list = document.getElementById("warningList");
  list.innerHTML = item.findings.length
    ? item.findings.map(f => `
      <div class="ss-warning">
        <div><b>⚠️ ${esc(f.name)}</b><strong>+${f.points}</strong></div>
        <p>${esc(f.detail || "")}</p>
      </div>`).join("")
    : `<div class="ss-warning">
        <b>✓ No listed warning pattern matched</b>
        <p>This does not guarantee that the message is genuine or safe.</p>
      </div>`;

  document.getElementById("recommendationText").textContent = item.advice;

  let lang = document.getElementById("ssLanguageResult");
  if (lang) lang.textContent = "Detected text type: " + item.language;

  const rec = document.querySelector(".recommendation");
  let actions = document.getElementById("ssReportActions");

  if (rec && !actions) {
    actions = document.createElement("div");
    actions.id = "ssReportActions";
    actions.className = "d-flex flex-wrap gap-2 mt-3";
    rec.appendChild(actions);
  }

  if (actions) {
    actions.innerHTML = `
      <button type="button" class="btn btn-analyze" id="ssCopyAdvice">Copy Safety Advice</button>
      <button type="button" class="btn btn-clear" id="ssDownloadReport">Download Report</button>`;

    document.getElementById("ssCopyAdvice").onclick = () => copyText(lastScan.advice);
    document.getElementById("ssDownloadReport").onclick = () =>
      download("ScamShield-Report.txt", report(lastScan));
  }
}

function saveScan(item) {
  scans.unshift(item);
  scans = scans.slice(0, MAX_HISTORY);
  saveHistory();
  renderHistory();
  renderAnalytics();
}

async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
    } else {
      const t = document.createElement("textarea");
      t.value = text;
      t.style.position = "fixed";
      t.style.opacity = "0";
      document.body.appendChild(t);
      t.select();
      const ok = document.execCommand("copy");
      t.remove();
      if (!ok) throw Error();
    }
    toast("Copied to clipboard.");
  } catch (_) {
    alert("Copy failed. Select the text and press Ctrl+C.");
  }
}

function download(name, content, type = "text/plain;charset=utf-8") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function report(x) {
  return [
    "SCAMSHIELD+ SCAN REPORT",
    "=======================",
    "Type: " + x.type,
    "Date: " + new Date(x.date).toLocaleString(),
    "Language: " + (x.language || languageOf(x.content)),
    "Risk: " + x.level + " (" + x.score + "/100)",
    "",
    "Scanned content:", x.content, "",
    "Warning signs:",
    ...(x.findings.length
      ? x.findings.map(f => "- " + f.name + " (+" + f.points + "): " + (f.detail || ""))
      : ["- None matched"]),
    "",
    "Advice:", x.advice, "",
    "Educational rule-based score only; not a calibrated fraud probability or live reputation check."
  ].join("\n");
}

function csvCell(x) {
  return '"' + String(x == null ? "" : x).replace(/"/g, '""') + '"';
}

function renderHistory() {
  const el = document.getElementById("historyList");
  if (!el) return;

  if (!scans.length) {
    el.innerHTML = '<p class="muted-text">No scans yet. Analyze a message to begin.</p>';
    return;
  }

  el.innerHTML = scans.slice(0, 12).map((x, i) => `
    <div class="ss-history-row">
      <div>
        <strong>${esc(x.type)} · ${esc(x.level)} Risk (${x.score}/100)</strong>
        <p>${esc(String(x.content || "").slice(0, 130))}</p>
        <small>${esc(new Date(x.date).toLocaleString())}</small>
      </div>
      <button class="btn btn-clear" data-rpt="${i}" type="button">Report</button>
    </div>`).join("");

  el.querySelectorAll("[data-rpt]").forEach(b => {
    b.onclick = () => download("ScamShield-Report.txt", report(scans[+b.dataset.rpt]));
  });
}

function exportHistory() {
  if (!scans.length) {
    toast("No scan history to export.");
    return;
  }

  const rows = [
    ["Type", "Content", "Risk", "Score", "Date", "Language", "Warnings", "Advice"],
    ...scans.map(x => [
      x.type, x.content, x.level, x.score,
      new Date(x.date).toLocaleString(), x.language,
      (x.findings || []).map(f => f.name).join("; "), x.advice
    ])
  ];

  download("ScamShield-History.csv",
    rows.map(r => r.map(csvCell).join(",")).join("\r\n"),
    "text/csv;charset=utf-8");
}

function renderAnalytics() {
  const root = document.getElementById("ssAnalytics");
  if (!root) return;

  const counts = { High: 0, Medium: 0, Low: 0 }, cats = {};
  scans.forEach(x => {
    counts[x.level] = (counts[x.level] || 0) + 1;
    (x.findings || []).forEach(f => {
      const k = f.category || f.name;
      cats[k] = (cats[k] || 0) + 1;
    });
  });

  const top = Object.entries(cats).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = Math.max(1, ...top.map(x => x[1]));
  const days = [];

  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() - i);
    const key = d.toLocaleDateString();
    days.push({
      label: d.toLocaleDateString(undefined, { weekday: "short" }),
      n: scans.filter(x => new Date(x.date).toLocaleDateString() === key).length
    });
  }

  const md = Math.max(1, ...days.map(d => d.n));

  root.innerHTML = `
    <div class="ss-stat-grid">
      <div class="ss-stat"><span>Total scans</span><b>${scans.length}</b></div>
      <div class="ss-stat"><span>High risk</span><b class="ss-high">${counts.High || 0}</b></div>
      <div class="ss-stat"><span>Medium risk</span><b class="ss-med">${counts.Medium || 0}</b></div>
      <div class="ss-stat"><span>Low risk</span><b class="ss-low">${counts.Low || 0}</b></div>
    </div>
    <div class="ss-chart-grid">
      <div class="ss-chart">
        <h3>Scans in last 7 days</h3>
        <div class="ss-week">
          ${days.map(d => `
            <div><b>${d.n}</b>
              <span class="ss-weektrack"><i style="height:${Math.max(d.n ? 8 : 2, d.n / md * 100)}%"></i></span>
              <small>${d.label}</small>
            </div>`).join("")}
        </div>
      </div>
      <div class="ss-chart">
        <h3>Common warning categories</h3>
        ${top.length ? top.map(([name, n]) => `
          <div class="ss-cat">
            <div><span>${esc(name)}</span><b>${n}</b></div>
            <div class="ss-track"><i style="width:${n / max * 100}%"></i></div>
          </div>`).join("") :
          '<p class="muted-text">Scan messages to build the chart.</p>'}
      </div>
    </div>
    <button id="ssExport" class="btn btn-clear mt-3" type="button">Export All History (CSV)</button>
    <p class="ss-note">Statistics come from scans saved in this browser, not global threat data.</p>`;

  document.getElementById("ssExport").onclick = exportHistory;
}

/* CSV reader that supports quoted commas and escaped quotation marks. */
function parseCSV(text) {
  const rows = [];
  let row = [], field = "", q = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];

    if (q) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') q = false;
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else if (c !== "\r") field += c;
  }

  row.push(field);
  if (row.some(v => v.trim())) rows.push(row);
  return rows;
}

function getMessages(text, name) {
  if (/\.txt$/i.test(name)) {
    return text.split(/\r?\n/).map(x => x.trim()).filter(Boolean);
  }

  const rows = parseCSV(text);
  if (!rows.length) return [];

  const heads = rows[0].map(v => v.trim().toLowerCase().replace(/[ _-]/g, ""));
  const idx = heads.findIndex(v =>
    ["message", "text", "email", "content", "body", "sms", "emailbody"].includes(v)
  );

  const data = idx >= 0 ? rows.slice(1) : rows;

  return data.map(r => String(
    idx >= 0 ? r[idx] || "" :
      r.reduce((a, b) => String(b).length > String(a).length ? b : a, "") || ""
  ).trim()).filter(Boolean);
}

function runBulk(messages) {
  bulkResults = messages.map((text, i) => {
    const x = itemFor("Bulk message", text, analyze(text));
    x.row = i + 1;
    return x;
  });

  scans = [...bulkResults, ...scans].slice(0, MAX_HISTORY);
  saveHistory();
  renderHistory();
  renderAnalytics();
  showBulkResults();
  toast("Bulk scan completed: " + bulkResults.length + " messages.");
}

function showBulkResults() {
  const root = document.getElementById("ssBulkResults");
  if (!root) return;

  if (!bulkResults.length) {
    root.innerHTML = '<p class="muted-text">Choose a file and run a bulk scan.</p>';
    return;
  }

  const n = { High: 0, Medium: 0, Low: 0 };
  bulkResults.forEach(x => n[x.level]++);

  root.innerHTML = `
    <p><b>${bulkResults.length} scanned</b> ·
      <span class="ss-high">${n.High} high</span> ·
      <span class="ss-med">${n.Medium} medium</span> ·
      <span class="ss-low">${n.Low} low</span>
    </p>
    <div class="ss-tablewrap">
      <table class="table table-sm">
        <thead><tr><th>#</th><th>Message preview</th><th>Risk</th><th>Score</th><th>Warning signs</th></tr></thead>
        <tbody>
          ${bulkResults.map((x, i) => `
            <tr>
              <td>${i + 1}</td>
              <td>${esc(x.content.slice(0, 130))}</td>
              <td><span class="ss-pill ${x.level.toLowerCase()}">${x.level}</span></td>
              <td>${x.score}/100</td>
              <td>${esc(x.findings.map(f => f.name).join(", ") || "None detected")}</td>
            </tr>`).join("")}
        </tbody>
      </table>
    </div>
    <button id="ssBulkCsv" class="btn btn-analyze mt-2" type="button">Download Results CSV</button>
    <button id="ssBulkTxt" class="btn btn-clear mt-2" type="button">Download Text Report</button>`;

  document.getElementById("ssBulkCsv").onclick = () => {
    const rows = [
      ["Row", "Message", "Risk", "Score", "Language", "Warnings", "Advice"],
      ...bulkResults.map((x, i) => [
        i + 1, x.content, x.level, x.score, x.language,
        x.findings.map(f => f.name).join("; "), x.advice
      ])
    ];
    download("ScamShield-Bulk-Results.csv",
      rows.map(r => r.map(csvCell).join(",")).join("\r\n"),
      "text/csv;charset=utf-8");
  };

  document.getElementById("ssBulkTxt").onclick = () =>
    download("ScamShield-Bulk-Report.txt",
      bulkResults.map(report).join("\n\n--------------------\n\n"));
}

/* Screenshot OCR uses Tesseract.js loaded from a CDN when requested. */
function loadTesseract() {
  return new Promise((resolve, reject) => {
    if (window.Tesseract) return resolve();

    const s = document.createElement("script");
    s.src = "https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js";
    s.onload = resolve;
    s.onerror = () => reject(Error("OCR library could not load. Check your internet connection."));
    document.head.appendChild(s);
  });
}

async function runOCR() {
  const file = document.getElementById("ssImage").files[0];
  const out = document.getElementById("ssOCRText");
  const status = document.getElementById("ssOCRStatus");
  const btn = document.getElementById("ssOCRButton");

  if (!file) {
    toast("Choose a screenshot first.");
    return;
  }

  if (!file.type.startsWith("image/")) {
    toast("Select an image file.");
    return;
  }

  btn.disabled = true;
  status.textContent = "Loading OCR engine and language data…";
  out.value = "";

  try {
    await loadTesseract();
    let result;

    try {
      result = await Tesseract.recognize(file, "eng+tel", {
        logger: m => {
          if (m.status) status.textContent = "OCR: " + m.status +
            (typeof m.progress === "number" ? " " + Math.round(m.progress * 100) + "%" : "");
        }
      });
    } catch (_) {
      status.textContent = "Telugu OCR data unavailable; trying English…";
      result = await Tesseract.recognize(file, "eng", {
        logger: m => {
          if (m.status) status.textContent = "OCR: " + m.status;
        }
      });
    }

    out.value = (result.data.text || "").trim();

    if (out.value) {
      document.getElementById("messageInput").value = out.value;
      updateCount();
      status.textContent = "Text extracted. Review it, then click Analyze Extracted Text.";
    } else {
      status.textContent = "No readable text found. Try a clearer screenshot.";
    }
  } catch (e) {
    status.textContent = "OCR failed: " + e.message + ". You can paste the message manually.";
  } finally {
    btn.disabled = false;
  }
}

function updateCount() {
  const i = document.getElementById("messageInput");
  const c = document.getElementById("charCount");
  if (i && c) c.textContent = i.value.length + " / 10000";
}

/* Add the OCR, analytics and bulk scanner sections without editing index.html. */
function addUI() {
  const main = document.querySelector("main.main-content");
  const info = main && main.querySelector(".info-section");
  if (!main) return;

  const analytics = document.createElement("section");
  analytics.id = "ssAnalyticsSection";
  analytics.className = "glass-card my-4 p-3 p-md-4";
  analytics.innerHTML = '<h2>Scan Analytics</h2><p class="muted-text">Statistics from scans saved in this browser.</p><div id="ssAnalytics"></div>';
  main.insertBefore(analytics, info || null);

  const ocr = document.createElement("section");
  ocr.className = "glass-card my-4 p-3 p-md-4";
  ocr.innerHTML = `
    <h2>Screenshot Scam Detector</h2>
    <p class="muted-text">Extract text from a screenshot, then analyze it. OCR needs an internet connection on first use.</p>
    <label class="form-label" for="ssImage">Screenshot image</label>
    <input class="form-control" id="ssImage" type="file" accept="image/*">
    <button class="btn btn-analyze mt-3" id="ssOCRButton" type="button">Extract Screenshot Text</button>
    <button class="btn btn-clear mt-3 ms-2" id="ssAnalyzeOCR" type="button">Analyze Extracted Text</button>
    <p class="muted-text mt-3" id="ssOCRStatus">No screenshot selected.</p>
    <label class="form-label" for="ssOCRText">Extracted text (editable)</label>
    <textarea class="form-control" id="ssOCRText" rows="5" placeholder="Extracted text appears here…"></textarea>
    <p class="ss-note">OCR can misread text; review it before analyzing.</p>`;
  main.insertBefore(ocr, info || null);

  const bulk = document.createElement("section");
  bulk.className = "glass-card my-4 p-3 p-md-4";
  bulk.innerHTML = `
    <h2>Bulk Message Scanner</h2>
    <p class="muted-text">Upload CSV with a message/text/email/content/body column, or TXT with one message per line.</p>
    <input class="form-control" id="ssBulkFile" type="file" accept=".csv,.txt,text/csv,text/plain">
    <button class="btn btn-analyze mt-3" id="ssRunBulk" type="button">Scan File</button>
    <button class="btn btn-clear mt-3 ms-2" id="ssTemplate" type="button">Download Sample CSV</button>
    <p class="muted-text mt-3" id="ssBulkStatus">No file selected.</p>
    <div id="ssBulkResults"></div>`;
  main.insertBefore(bulk, info || null);

  const exportBtn = document.createElement("button");
  exportBtn.id = "ssExportHistory";
  exportBtn.type = "button";
  exportBtn.className = "btn btn-clear ms-2";
  exportBtn.textContent = "Export History CSV";
  exportBtn.onclick = exportHistory;

  const histRow = document.querySelector(".history-section .d-flex");
  if (histRow) histRow.appendChild(exportBtn);

  const st = document.createElement("style");
  st.textContent = `
    #ssToast{position:fixed;z-index:9999;bottom:20px;left:50%;transform:translateX(-50%);background:#172438;color:white;padding:12px 18px;border-radius:10px;opacity:0;pointer-events:none;transition:opacity .2s;max-width:90vw}
    #ssToast.show{opacity:1}
    .ss-stat-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:16px 0}
    .ss-stat,.ss-chart{border:1px solid #8884;border-radius:12px;padding:14px;min-width:0}
    .ss-stat span{display:block}.ss-stat b{font-size:1.8rem}
    .ss-high{color:#e45462}.ss-med{color:#cc8c21}.ss-low{color:#249b78}
    .ss-chart-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
    .ss-chart h3{font-size:1rem}
    .ss-week{height:160px;display:flex;gap:8px;justify-content:space-around}
    .ss-week>div{display:flex;align-items:center;flex-direction:column;gap:5px;flex:1}
    .ss-weektrack{height:115px;width:100%;max-width:32px;display:flex;align-items:flex-end;background:#8882;margin-top:auto;border-radius:6px;overflow:hidden}
    .ss-weektrack i{width:100%;background:#4788e8}.ss-week small{font-size:.75rem}
    .ss-cat{margin:10px 0}.ss-cat>div:first-child{display:flex;justify-content:space-between;gap:8px}
    .ss-track{height:8px;background:#8882;border-radius:8px;overflow:hidden}
    .ss-track i{display:block;height:100%;background:#4788e8}
    .ss-note{font-size:.85rem;opacity:.8}
    .ss-warning{border:1px solid #8884;border-radius:9px;padding:10px;margin:8px 0}
    .ss-warning>div{display:flex;justify-content:space-between;gap:8px}
    .ss-warning p{margin:5px 0 0;opacity:.85}
    .ss-history-row{display:flex;justify-content:space-between;gap:12px;padding:12px 0;border-bottom:1px solid #8884}
    .ss-history-row p{margin:5px 0;overflow-wrap:anywhere}
    .ss-tablewrap{overflow:auto}.ss-tablewrap table{min-width:700px;color:inherit}
    .ss-tablewrap td{max-width:350px;overflow-wrap:anywhere}
    .ss-pill{border-radius:20px;padding:4px 8px;font-size:.8rem}
    .ss-pill.high{background:#fde1e3;color:#98202a}
    .ss-pill.medium{background:#fff0cf;color:#80510a}
    .ss-pill.low{background:#d8f4e8;color:#176444}
    @media(max-width:700px){.ss-stat-grid{grid-template-columns:repeat(2,1fr)}.ss-chart-grid{grid-template-columns:1fr}.ss-history-row{flex-direction:column}}
  `;
  document.head.appendChild(st);
}

document.addEventListener("DOMContentLoaded", () => {
  addUI();

  const input = document.getElementById("messageInput");

  document.getElementById("analyzeBtn").addEventListener("click", analyzeButton);

  input.addEventListener("input", () => {
    updateCount();
    clearErr();
  });

  input.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyzeButton();
  });

  document.getElementById("clearBtn").addEventListener("click", () => {
    input.value = "";
    updateCount();
    clearErr();
    document.getElementById("resultSection").hidden = true;
    document.getElementById("emptyState").hidden = false;
    input.focus();
  });

  document.querySelectorAll("[data-sample]").forEach(b => b.addEventListener("click", () => {
    input.value = samples[b.dataset.sample] || "";
    updateCount();
    clearErr();
    input.focus();
  }));

  document.getElementById("clearHistoryBtn").addEventListener("click", () => {
    if (!scans.length) return toast("History is already empty.");
    if (confirm("Clear all scan history saved in this browser?")) {
      scans = [];
      saveHistory();
      renderHistory();
      renderAnalytics();
    }
  });

  document.getElementById("ssOCRButton").addEventListener("click", runOCR);

  document.getElementById("ssAnalyzeOCR").addEventListener("click", () => {
    const t = document.getElementById("ssOCRText").value.trim();
    if (!t) return toast("Extract or paste text first.");
    input.value = t;
    updateCount();
    analyzeButton();
  });

  document.getElementById("ssBulkFile").addEventListener("change", e => {
    const f = e.target.files[0];
    document.getElementById("ssBulkStatus").textContent =
      f ? "Selected: " + f.name : "No file selected.";
  });

  document.getElementById("ssRunBulk").addEventListener("click", async () => {
    const f = document.getElementById("ssBulkFile").files[0];
    if (!f) return toast("Choose a CSV or TXT file first.");
    if (f.size > 5 * 1024 * 1024) return toast("Use a file smaller than 5 MB.");

    try {
      const messages = getMessages(await f.text(), f.name);
      if (!messages.length) return toast("No messages found. Check the file format.");
      if (messages.length > 1000) return toast("Scan up to 1,000 rows at a time.");
      document.getElementById("ssBulkStatus").textContent = "Scanned " + messages.length + " messages.";
      runBulk(messages);
    } catch (e) {
      toast("Could not read this file.");
    }
  });

  document.getElementById("ssTemplate").addEventListener("click", () => {
    download(
      "ScamShield-Sample-Messages.csv",
      "message\r\n" + [
        samples.scam, samples.safe, samples.link,
        "Congratulations! Claim the money by clicking the link below."
      ].map(csvCell).join("\r\n"),
      "text/csv;charset=utf-8"
    );
  });

  renderHistory();
  renderAnalytics();
  updateCount();
});
