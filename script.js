const demo={metrics:{scanned:0,high:0,spoofed:0,campaigns:0},emails:[],campaigns:[],alerts:[]};
const routes={dashboard:"Overview", "email-analysis":"Email Analysis", investigations:"Investigations","threat-intelligence":"Threat Intelligence",geolocation:"GeoLocation",infrastructure:"Infrastructure Graph","forensic-reports":"Forensic Reports",evidence:"Evidence",alerts:"Security Alerts",settings:"Settings"};

const view=document.getElementById("view"), pageCrumb=document.getElementById("pageCrumb");
let charts={};

function shell(title,sub,actions=""){return `<div class="page-head"><div><div class="eyebrow"></div><h1>${title}</h1><p>${sub}</p></div><div>${actions}</div></div>`}
function cardHead(title,right=""){return `<div class="card-head"><span class="card-title">${title}</span>${right}</div>`}
function badge(r){return `<span class="badge ${r.toLowerCase()}">${r}</span>`}
function toast(msg){const r=document.getElementById("toastRoot");r.innerHTML=`<div class="toast"><b>✓</b> ${msg}</div>`;setTimeout(()=>r.innerHTML="",2800)}
function modal(title,body,buttons=`<button class="btn" data-close>Close</button>`){document.getElementById("modalRoot").innerHTML=`<div class="modal-backdrop"><div class="modal"><div class="modal-head"><h3>${title}</h3><button class="icon-btn" data-close>×</button></div><div class="modal-body">${body}</div><div class="modal-foot">${buttons}</div></div></div>`}
function bindCommon(){document.querySelectorAll("[data-close]").forEach(x=>x.onclick=()=>document.getElementById("modalRoot").innerHTML="");document.querySelectorAll("[data-toast]").forEach(x=>x.onclick=()=>toast(x.dataset.toast));document.querySelectorAll(".switch").forEach(x=>x.onclick=()=>x.classList.toggle("on"))}

function dashboard(){
  const scans = SM.state.scans || [];
  const total = scans.length;
  const high = scans.filter(x => ['HIGH','CRITICAL'].includes(x.risk)).length;
  const spoofed = scans.filter(x => x.classification === 'IMPERSONATION' || x.spoofed).length;
  const campaigns = new Set(scans.map(x => x.campaign).filter(Boolean)).size;
  const avg = total ? Math.round(scans.reduce((a,x)=>a + Number(x.score || 0),0) / total) : 0;

  view.innerHTML=shell("Security Overview","Email threat detection and forensic intelligence command center");
  view.innerHTML+=`<div class="kpis">
    ${kpi("Total Scanned",String(total),total?"Uploaded emails":"No emails analyzed","✉")}
    ${kpi("High-Risk Threats Detected",String(high),total?"From analyzed emails":"No data yet","⚠")}
    ${kpi("Spoofed Domains Detected",String(spoofed),total?"From analyzed emails":"No data yet","◈")}
    ${kpi("Average Risk Score",total?avg+"%":"—",total?"From analyzed emails":"No data yet","◎")}
  </div>
  <div class="dashboard-grid">
    <div class="card chart-card">${cardHead("THREAT CLASSIFICATION","<span class='muted'>Uploaded emails only</span>")}<div class="chart-wrap">${total?'<canvas id="threatChart"></canvas>':'<div class="empty-state">No analyzed emails yet.<br><span class="muted">Upload an .eml file from Email Analysis.</span></div>'}</div></div>
    <div class="card chart-card">${cardHead("RISK DISTRIBUTION","<span class='muted'>Uploaded emails only</span>")}<div class="chart-wrap">${total?'<canvas id="riskChart"></canvas>':'<div class="empty-state">No risk data yet.</div>'}</div></div>
  </div>
  <div class="card table-card">${cardHead("RECENT SCANS","<button class='btn' onclick=\"location.hash='email-analysis'\">Analyze Email</button>")}
    <div class="table-wrap"><table class="table"><thead><tr><th>TIMESTAMP</th><th>TARGET</th><th>SENDER</th><th>SUBJECT</th><th>CLASSIFICATION</th><th>FRAUD SCORE</th><th>RISK</th><th>STATUS</th><th>ACTION</th></tr></thead>
    <tbody>${total ? scans.slice().reverse().map(e=>`<tr><td>${SM.esc(e.time||e.timestamp||"—")}</td><td>${SM.esc(e.employee||"—")}</td><td>${SM.esc(e.from||e.sender||"—")}</td><td>${SM.esc(e.subject||"—")}</td><td>${badge(e.classification||e.class||"ANALYZED")}</td><td><span class="progress"><i style="width:${Number(e.score||0)}%"></i></span>${Number(e.score||0)}%</td><td>${badge(e.risk||"LOW")}</td><td>${SM.esc(e.status||"Analyzed")}</td><td><button class="btn" onclick="location.hash='report/${encodeURIComponent(e.id)}'">View Report</button></td></tr>`).join("") : `<tr><td colspan="9" class="muted" style="padding:30px;text-align:center">No emails analyzed yet. Upload an .eml file to populate this dashboard.</td></tr>`}</tbody></table></div>
  </div>
  <div class="two-col section-gap">
    <div class="card">${cardHead("ACTIVE THREAT CAMPAIGNS")}<div class="list">${campaigns ? [...new Set(scans.map(x=>x.campaign).filter(Boolean))].map(c=>`<div class="campaign"><strong>${SM.esc(c)}</strong><p>${scans.filter(x=>x.campaign===c).length} analyzed email(s)</p></div>`).join("") : '<div class="empty-state">No campaign data available.</div>'}</div></div>
    <div class="card">${cardHead("RECENT SECURITY ALERTS")}<div class="list">${total ? scans.filter(x=>x.risk==='CRITICAL'||x.risk==='HIGH').slice(-5).reverse().map(x=>`<div class="list-item"><div class="alert-main"><i class="alert-dot"></i><div><strong>${SM.esc(x.subject||"High-risk email")}</strong><span>${SM.esc(x.id||"")}</span></div></div>${badge(x.risk)}</div>`).join("") || '<div class="empty-state">No high-risk alerts.</div>' : '<div class="empty-state">No security alerts yet.</div>'}</div></div>
  </div>
  <div class="card section-gap">${cardHead("SYSTEM STATUS")}<div class="three-col" style="padding:12px">${["AI Engine","Email Parser","Threat Intelligence","Database","GeoLocation","Evidence Store"].map(x=>`<div class="status-line"><i class="green"></i><span>${x}</span><span class="muted" style="margin-left:auto">FRONTEND READY</span></div>`).join("")}</div></div>`;
  if(total) renderCharts();
}

function kpi(l,n,t,ic){return `<div class="card kpi"><div class="kpi-top"><span>${l}</span><span class="kpi-icon">${ic}</span></div><div class="kpi-num">${n}</div><span class="trend">${t}</span></div>`}

function renderCharts(){
  charts.threat?.destroy();
  charts.risk?.destroy();
  const scans = SM.state.scans || [];
  if(!scans.length) return;

  const isDark = document.documentElement.getAttribute("data-theme") === "dark";

  const colors = isDark ? {
    threat: ["#FF477E", "#FF8A00", "#7542FF", "#FFB800", "#D4FF00"],
    risk: ["#FF477E", "#FF8A00", "#FFB800", "#D4FF00"],
    donutBorder: "#13141C",
    text: "#7E8B9B",
    grid: "rgba(255, 255, 255, 0.06)",
    legend: "#A0AEC0"
  } : {
    threat: ["#FF5C5C", "#FF754C", "#6C5DD3", "#FFB017", "#00D2D3"],
    risk: ["#FF5C5C", "#FF754C", "#FFB017", "#00D2D3"],
    donutBorder: "#FFFFFF",
    text: "#808191",
    grid: "rgba(0, 0, 0, 0.05)",
    legend: "#808191"
  };

  const classLabels = ["PHISHING","MALWARE","BEC","SUSPICIOUS","LIKELY LEGITIMATE"];
  const classCounts = classLabels.map(label => scans.filter(x => String(x.classification||"").toUpperCase() === label).length);
  const riskLabels = ["CRITICAL","HIGH","MEDIUM","LOW"];
  const riskCounts = riskLabels.map(label => scans.filter(x => String(x.risk||"").toUpperCase() === label).length);

  const threatEl = document.getElementById("threatChart");
  if(threatEl) {
    charts.threat = new Chart(threatEl, {
      type: "bar",
      data: {
        labels: classLabels,
        datasets: [{
          label: "Uploaded emails",
          data: classCounts,
          backgroundColor: colors.threat,
          borderWidth: 0,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: colors.text, font: { size: 8 } } },
          y: { beginAtZero: true, grid: { color: colors.grid }, ticks: { color: colors.text, font: { size: 8 }, precision: 0 } }
        }
      }
    });
  }

  const riskEl = document.getElementById("riskChart");
  if(riskEl) {
    charts.risk = new Chart(riskEl, {
      type: "doughnut",
      data: {
        labels: riskLabels,
        datasets: [{
          data: riskCounts,
          backgroundColor: colors.risk,
          borderWidth: 2,
          borderColor: colors.donutBorder
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "right",
            labels: { color: colors.legend, font: { size: 9 }, boxWidth: 10 }
          }
        }
      }
    });
  }
}

function chartOpts(){return{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:"#94a7bd",font:{size:9},boxWidth:12}}},scales:{x:{grid:{color:"rgba(100,120,145,.08)"},ticks:{color:"#687b94",font:{size:8}}},y:{grid:{color:"rgba(100,120,145,.08)"},ticks:{color:"#687b94",font:{size:8}}}}}}

function emailAnalysis(){view.innerHTML=shell("Email Threat Analysis","Upload and investigate suspicious email evidence.");view.innerHTML+=`<div class="two-col analysis-layout"><div class="card analysis-upload-card"><div class="upload" id="drop"><div class="upload-icon">⇧</div><h3>DROP .EML FILE HERE</h3><p>OR</p><button class="btn primary" id="browse">Browse Files</button><p>Supported format: .EML · Maximum size: 25 MB</p><input id="fileInput" type="file" accept=".eml" class="hidden"></div><div id="fileInfo" class="hidden"></div></div><div class="card">${cardHead("")}<div style="padding:15px"><div class="notice"></div><div style="margin-top:14px">${resultSummary()}</div></div></div></div><div class="card section-gap">${cardHead("HEADER FORENSICS")}<div class="auth-grid">${auth("SPF","PASS","pass")}${auth("DKIM","FAIL","fail")}${auth("DMARC","FAIL","fail")}</div><div class="email-meta">${meta("From","SBI Corporate Banking <alerts@sbi-corp-demo.test>")}${meta("To","finance@company-demo.test")}${meta("Subject","Urgent Corporate Invoice Verification Required")}${meta("Reply-To","verify@secure-banking-demo.test")}${meta("Return-Path","bounce@mailer-demo.test")}${meta("Message-ID","<20260831.204218@demo.test>")}</div></div><div class="card section-gap">${cardHead("RAW EMAIL HEADERS","<span class='badge low'></span>")}<details><summary style="padding:13px 15px;cursor:pointer;color:#9db0c5;font-size:10px">RAW EMAIL HEADERS</summary><pre class="code">Received: from mailer-demo.test (203.0.113.42) by mx.company-demo.test
From: SBI Corporate Banking &lt;alerts@sbi-corp-demo.test&gt;
To: finance@company-demo.test
Subject: Urgent Corporate Invoice Verification Required
Date: Mon, 31 Aug 2026 20:42:18 +0530
Message-ID: &lt;20260831.204218@demo.test&gt;
Return-Path: bounce@mailer-demo.test
Reply-To: verify@secure-banking-demo.test
Authentication-Results: spf=pass; dkim=fail; dmarc=fail
Received-SPF: pass
DKIM-Signature: v=1; d=secure-banking-demo.test; s=demo;</pre></details></div><div class="two-col section-gap"><div class="card">${cardHead("HEADER RELAY PATH")}<div class="timeline"><div class="timeline-item"><div class="timeline-time">1</div><div class="timeline-line"></div><div class="timeline-body"><strong>Sender</strong><p>Fictional sender identity</p></div></div><div class="timeline-item"><div class="timeline-time">2</div><div class="timeline-line"></div><div class="timeline-body"><strong>Mail Server</strong><p>Demo relay infrastructure</p></div></div><div class="timeline-item"><div class="timeline-time">3</div><div class="timeline-line"></div><div class="timeline-body"><strong>Relay Server</strong><p>Observed intermediary</p></div></div><div class="timeline-item"><div class="timeline-time">4</div><div class="timeline-line"></div><div class="timeline-body"><strong>Observed Sending Node</strong><p>203.0.113.42</p></div></div></div><div class="notice" style="margin:0 14px 14px">An observed sending node does not necessarily represent the attacker's physical location.</div></div><div class="card">${cardHead("OBSERVED NETWORK INDICATORS")}<div class="email-meta">${meta("IP","203.0.113.42")}${meta("Domain","secure-banking-demo.test")}${meta("URL","https://login-demo.test/a")}${meta("File Hash","9f4d7e2b...d1a93f")}</div></div></div>`;bindUpload();bindCommon()}
function resultSummary(){return `<div class="result-header" style="padding:0"><div><span class="badge high">THREAT LEVEL · HIGH</span><h2 style="font-size:18px;margin:10px 0 4px">PHISHING</h2><p class="muted" style="font-size:10px">AI classification is an assessment and should be reviewed by an analyst.</p></div><div style="text-align:right"><div class="risk-score">94/100</div><span class="muted" style="font-size:9px">MODEL CONFIDENCE 96%</span></div></div><div class="tactics"><span class="tactic">URGENCY LANGUAGE</span><span class="tactic">SUSPICIOUS SENDER</span><span class="tactic">CREDENTIAL HARVESTING</span><span class="tactic">SUSPICIOUS URL</span><span class="tactic">AUTHORITY BIAS</span></div>`}
function auth(a,b,c){return `<div class="auth"><b>${a}</b><strong class="${c}">● ${b}</strong><span class="muted" style="font-size:8px">Alignment check</span></div>`}
function meta(a,b){return `<div class="meta"><label>${a}</label><span>${b}</span></div>`}
function bindUpload(){const inp=document.getElementById("fileInput"),browse=document.getElementById("browse"),drop=document.getElementById("drop");browse.onclick=()=>inp.click();inp.onchange=()=>{if(inp.files[0])showFile(inp.files[0])};drop.ondragover=e=>{e.preventDefault();drop.style.borderColor="var(--cyan)"};drop.ondragleave=()=>drop.style.borderColor="";drop.ondrop=e=>{e.preventDefault();drop.style.borderColor="";if(e.dataTransfer.files[0])showFile(e.dataTransfer.files[0])}}
function showFile(f){document.getElementById("fileInfo").classList.remove("hidden");document.getElementById("fileInfo").innerHTML=`<div style="padding:13px;border-top:1px solid var(--border)"><b style="font-size:10px">${f.name}</b><span class="muted" style="font-size:9px;margin-left:8px">${(f.size/1024).toFixed(1)} KB</span><span class="badge verified" style="float:right">READY</span><button class="btn primary" style="margin-top:10px;width:100%" onclick="toast('Demo email analysis completed — 94/100 risk')">Analyze Email</button></div>`}

function investigations(){view.innerHTML=shell("Investigation Cases","Manage cases, evidence, analysts and forensic workflows.",`<button class="btn primary" id="createCase">＋ Create Investigation</button>`);view.innerHTML+=`<div class="card"><div style="padding:13px;display:flex;gap:8px;flex-wrap:wrap"><input class="field" id="caseSearch" placeholder="Search cases..." style="background:#091523;border:1px solid #23364f;color:#dbe7f4;border-radius:6px;padding:9px;font:10px Inter;flex:1;min-width:180px"><select id="riskFilter" class="field" style="background:#091523;border:1px solid #23364f;color:#dbe7f4;border-radius:6px;padding:9px;font:10px Inter"><option>All Risk</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option></select></div><div class="table-wrap"><table class="table"><thead><tr><th>CASE ID</th><th>TITLE</th><th>CLASSIFICATION</th><th>RISK</th><th>PRIORITY</th><th>STATUS</th><th>ANALYST</th><th>CREATED</th><th>ACTION</th></tr></thead><tbody id="caseRows"></tbody></table></div></div>`;const cases=[["CASE-001","Urgent Account Verification","PHISHING / IMPERSONATION","CRITICAL","CRITICAL","INVESTIGATING","Security Analyst","31 Aug 2026"],["CASE-002","M365 Credential Harvest","PHISHING","HIGH","HIGH","OPEN","Security Analyst","31 Aug 2026"],["CASE-003","Vendor Invoice Anomaly","FRAUD","HIGH","MEDIUM","REVIEW","Security Analyst","30 Aug 2026"],["CASE-004","Executive Impersonation","BEC","MEDIUM","HIGH","CLOSED","Security Analyst","29 Aug 2026"]];function fill(){let q=(document.getElementById("caseSearch").value||"").toLowerCase(),r=document.getElementById("riskFilter").value;document.getElementById("caseRows").innerHTML=cases.filter(c=>(!q||c.join(" ").toLowerCase().includes(q))&&(r==="All Risk"||c[3]===r)).map(c=>`<tr>${c.slice(0,8).map((x,i)=>`<td>${i===3||i===4?badge(x):x}</td>`).join("")}<td><button class="btn" onclick="location.hash='investigations/001'">Open</button></td></tr>`).join("")}fill();document.getElementById("caseSearch").oninput=fill;document.getElementById("riskFilter").onchange=fill;document.getElementById("createCase").onclick=()=>createCaseModal();bindCommon()}
function createCaseModal(){modal("CREATE INVESTIGATION",`<div class="form-grid"><div class="field"><label>Case Title</label><input id="ct" value=""></div><div class="field"><label>Priority</label><select><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option></select></div><div class="field"><label>Classification</label><select><option>PHISHING</option><option>IMPERSONATION</option><option>FRAUD</option><option>BEC</option></select></div><div class="field"><label>Assigned Analyst</label><input value="Security Analyst"></div><div class="field full"><label>Description</label><textarea placeholder="Investigation description"></textarea></div></div>`,`<button class="btn" data-close>Cancel</button><button class="btn primary" id="saveCase">Create Case</button>`);document.getElementById("saveCase").onclick=()=>{document.getElementById("modalRoot").innerHTML="";toast("Investigation created successfully in demo mode.")}}

function report(id) {
  const d = (SM.state.scans || []).find(x => x.id === id);
  if (!d) {
    view.innerHTML = shell(
      "Report Not Found",
      "The requested investigation report does not exist.",
      `<button class="btn primary" onclick="location.hash='dashboard'">Back to Dashboard</button>`
    );
    view.innerHTML += `<div class="card"><div class="empty"><strong>No matching report</strong><p class="muted">This investigation ID was not found in local storage.</p></div></div>`;
    bindCommon();
    return;
  }

  let html = `<div class="card" style="margin-bottom:12px">
    <div class="result-header">
      <div>
        <div class="eyebrow">INVESTIGATION REPORT · ${SM.esc(d.id)}</div>
        <h1 style="font-size:25px;margin:0 0 7px">${SM.esc(d.classification)}</h1>
        <div class="stat-row">
          <span>Risk <b>${SM.esc(d.risk)}</b></span>
          <span>Score <b>${d.score}/100</b></span>
          <span>Uploaded <b>${SM.esc(d.time)}</b></span>
        </div>
      </div>
      <div style="text-align:right">
        <div class="risk-score">${d.score}%</div>
        <span class="muted" style="font-size:9px">FRAUD CONFIDENCE</span>
      </div>
    </div>
    <div style="padding:0 18px 18px;display:flex;gap:7px;flex-wrap:wrap">
      <button class="btn primary" data-toast="PDF generation will be connected to the backend in the next development stage.">Generate PDF Report</button>
      <button class="btn danger" id="take">Issue Takedown Notice</button>
      <button class="btn success" id="safe">Mark as Safe</button>
    </div>
  </div>`;

  html += `<div class="two-col">
    <div class="card">
      ${cardHead("EMAIL EVIDENCE")}
      <div class="email-meta" style="padding:0 15px 15px;">
        ${meta("From", SM.esc(d.from || "—"))}
        ${meta("To", SM.esc(d.to || "—"))}
        ${meta("Subject", SM.esc(d.subject || "—"))}
        ${meta("Date", SM.esc(d.date || "—"))}
        ${meta("Message-ID", SM.esc(d.messageId || "—"))}
        ${meta("Reply-To", SM.esc(d.reply || "—"))}
        ${meta("Return-Path", SM.esc(d.returnPath || "—"))}
      </div>
    </div>
    <div class="card">
      ${cardHead("AUTHENTICATION RESULTS")}
      <div class="auth-grid">${authDynamic("SPF", d.spf)}${authDynamic("DKIM", d.dkim)}${authDynamic("DMARC", d.dmarc)}</div>
      <div class="email-meta" style="padding:0 15px 15px;">
        ${meta("Sender Domain", SM.esc(d.fromDomain || "—"))}
        ${meta("Reply‑To Domain", SM.esc(d.replyDomain || "—"))}
        ${meta("Return‑Path Domain", SM.esc(d.returnDomain || "—"))}
      </div>
    </div>
  </div>`;

  html += `<div class="card section-gap">
    ${cardHead("OBSERVED INDICATORS")}
    <div class="email-meta" style="padding:0 15px 15px;">
      ${meta("IPs", (d.ips || []).length ? d.ips.map(SM.esc).join(', ') : 'None found')}
      ${meta("URLs", (d.urls || []).length ? d.urls.map(SM.esc).join('<br>') : 'None found')}
      ${meta("File SHA-256", SM.esc(d.hash || "—"))}
      ${meta("Received Hops", String(d.received?.length || 0))}
    </div>
  </div>`;

  html += `<div class="card section-gap">
    ${cardHead("AI ASSESSMENT & REASONS")}
    <div class="tactics" style="padding:10px 15px;">
      ${(d.reasons && d.reasons.length) 
        ? d.reasons.map(r => `<span class="tactic">${SM.esc(r.toUpperCase())}</span>`).join('') 
        : '<span class="muted">No suspicious indicators found (or this report was generated before reasons were stored).</span>'}
    </div>
  </div>`;

  html += `<div class="card section-gap">
    ${cardHead("RAW EMAIL HEADERS")}
    <details>
      <summary style="padding:13px 15px;cursor:pointer;color:#9db0c5;font-size:10px">VIEW RAW HEADERS</summary>
      <pre class="code">${SM.esc(d.raw || '')}</pre>
    </details>
  </div>`;

  if (d.rawFull) {
    html += `<div class="card section-gap">
      ${cardHead("FULL RAW EMAIL (Headers + Body)")}
      <details>
        <summary style="padding:13px 15px;cursor:pointer;color:#9db0c5;font-size:10px">VIEW FULL CONTENT</summary>
        <pre class="code" style="max-height:400px;overflow:auto;">${SM.esc(d.rawFull)}</pre>
      </details>
    </div>`;
  }

  html += `<div class="card section-gap">
    ${cardHead("EVIDENCE LOCKER")}
    <div class="email-meta" style="padding:0 15px 15px;">
      ${meta("File Name", SM.esc(d.fileName || "—"))}
      ${meta("File Size", SM.fmtBytes(d.size || 0))}
    </div>
    <div style="padding:0 15px 15px;">
      <button class="btn success" id="verifyReport">Verify Integrity</button>
      <span class="muted" style="font-size:9px;margin-left:9px">Blockchain provides tamper‑evident integrity records.</span>
    </div>
  </div>`;

  view.innerHTML = html;

  document.getElementById("take").onclick = () => modal(
    "TAKEDOWN NOTICE — DEMO DRAFT",
    `<div class="notice">DEMO DRAFT — NOT SENT</div>
     <div class="email-meta" style="padding-left:0;padding-right:0">
       ${meta("Suspicious Domain", SM.esc(d.fromDomain || "—"))}
       ${meta("Evidence Reference", SM.esc(d.id))}
       ${meta("Requested Action", "Review / Takedown")}
     </div>`
  );

  document.getElementById("safe").onclick = () => modal(
    "MARK REPORT AS SAFE",
    "Are you sure you want to mark this report as safe in demo mode?",
    `<button class="btn" data-close>Cancel</button>
     <button class="btn success" id="confirmSafe">Confirm</button>`
  );
  setTimeout(() => {
    document.getElementById("confirmSafe")?.addEventListener("click", () => {
      document.getElementById("modalRoot").innerHTML = "";
      toast("Report marked as safe in demo mode.");
    });
  }, 0);

  document.getElementById("verifyReport").onclick = () => {
    const btn = document.getElementById("verifyReport");
    btn.disabled = true;
    btn.textContent = "Verifying…";
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = "✓ Verified";
      toast("Evidence cryptographically verified — zero tampering detected.");
    }, 1200);
  };

  bindCommon();
}

function svgNode(x,y,title,type){return `<g class="node-svg" onclick="toast('${title} selected')"><circle cx="${x}" cy="${y}" r="25"/><text class="node-type" x="${x}" y="${y+3}" text-anchor="middle" font-size="9">${type}</text><text class="node-title" x="${x}" y="${y+43}" text-anchor="middle" font-size="8">${title}</text></g>`}

function simpleTable(title,sub,headers,rows,button){view.innerHTML=shell(title,sub);view.innerHTML+=`<div class="card">${cardHead(title.toUpperCase(),button?`<button class="btn primary" data-toast="${button}">${button}</button>`:"")}<div class="table-wrap"><table class="table"><thead><tr>${headers.map(h=>`<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map((x,i)=>`<td>${(x==="HIGH"||x==="CRITICAL"||x==="MEDIUM"||x==="LOW"||x==="VERIFIED"||x==="FAIL")?badge(x):x}</td>`).join("")}</tr>`).join("")}</tbody></table></div></div>`;bindCommon()}

function threatIntel() {
  const scans = SM.state.scans || [];
  view.innerHTML = shell("Threat Intelligence", "IP, domain, URL and file-hash reputation intelligence aggregated from uploaded emails.");

  const indicators = { IP: {}, DOMAIN: {}, URL: {}, 'FILE HASH': {} };
  const riskLevels = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
  const getScore = (risk) => riskLevels[risk] || 0;

  scans.forEach(scan => {
    const risk = scan.risk || 'LOW';
    const time = scan.time || '—';
    const score = getScore(risk);
    const invId = scan.id;

    const addIndicator = (type, value) => {
      if (!value) return;
      if (!indicators[type][value]) {
        indicators[type][value] = { maxScore: score, lastSeen: time, count: 0, invIds: [] };
      } else {
        if (score > indicators[type][value].maxScore) indicators[type][value].maxScore = score;
        if (time > indicators[type][value].lastSeen) indicators[type][value].lastSeen = time;
      }
      indicators[type][value].count++;
      if (!indicators[type][value].invIds.includes(invId)) {
        indicators[type][value].invIds.push(invId);
      }
    };

    (scan.ips || []).forEach(ip => addIndicator('IP', ip));
    [scan.fromDomain, scan.replyDomain, scan.returnDomain].filter(Boolean).forEach(d => addIndicator('DOMAIN', d));
    (scan.urls || []).forEach(u => addIndicator('URL', u));
    if (scan.hash) addIndicator('FILE HASH', scan.hash);
  });

  const indicatorData = {};
  Object.keys(indicators).forEach(type => {
    indicatorData[type] = Object.entries(indicators[type]).map(([value, data]) => ({
      value,
      type,
      maxScore: data.maxScore,
      lastSeen: data.lastSeen,
      count: data.count,
      invIds: data.invIds || [],
      reputation: data.maxScore >= 4 ? 'Malicious' : data.maxScore >= 3 ? 'Suspicious' : 'Unknown'
    }));
  });

  view.innerHTML += `<div class="card section-gap">
    <div style="padding:10px;display:flex;gap:6px;flex-wrap:wrap">
      <button class="btn primary" data-ti="IP">IP Intelligence</button>
      <button class="btn" data-ti="DOMAIN">Domain Intelligence</button>
      <button class="btn" data-ti="URL">URL Intelligence</button>
      <button class="btn" data-ti="FILE HASH">File Hash Intelligence</button>
      <span class="badge low" style="margin-left:auto;align-self:center">${scans.length} emails analyzed</span>
    </div>
    <div class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>INDICATOR</th>
            <th>TYPE</th>
            <th>REPUTATION</th>
            <th>SOURCE</th>
            <th>LAST CHECKED</th>
            <th>SEVERITY</th>
            <th>ACTION</th>
          </tr>
        </thead>
        <tbody id="tiRows"></tbody>
      </table>
    </div>
  </div>`;

  function showInvestigationModal(indicator, invIds) {
    if (!invIds || invIds.length === 0) {
      toast(`No investigations found for "${indicator}"`);
      return;
    }
    if (invIds.length === 1) {
      location.hash = `report/${encodeURIComponent(invIds[0])}`;
      return;
    }
    const links = invIds.map(id =>
      `<button class="btn" style="margin:4px;" onclick="location.hash='report/${encodeURIComponent(id)}'">${SM.esc(id)}</button>`
    ).join('');
    modal(
      `Investigations containing "${indicator}"`,
      `<p>Found ${invIds.length} investigation(s):</p><div style="display:flex;flex-wrap:wrap;gap:5px;">${links}</div>`
    );
  }

  const fillTable = (type) => {
    const rows = indicatorData[type] || [];
    const tbody = document.getElementById('tiRows');
    if (!tbody) return;

    tbody.innerHTML = rows.map(item => `
      <tr>
        <td>${SM.esc(item.value)}</td>
        <td>${item.type}</td>
        <td>${item.reputation}</td>
        <td>Local Analysis</td>
        <td>${SM.esc(item.lastSeen)}</td>
        <td>${badge(item.maxScore >= 4 ? 'CRITICAL' : item.maxScore >= 3 ? 'HIGH' : item.maxScore >= 2 ? 'MEDIUM' : 'LOW')}</td>
        <td><button class="btn investigate-btn" data-indicator="${SM.esc(item.value)}" data-invids="${item.invIds.join(',')}">Investigate</button></td>
      </tr>
    `).join('') || `<tr><td colspan="7" class="muted" style="padding:25px;text-align:center">No ${type.toLowerCase()} indicators found in uploaded emails.</td></tr>`;

    tbody.querySelectorAll('.investigate-btn').forEach(btn => {
      btn.onclick = function(e) {
        e.preventDefault();
        const indicator = this.dataset.indicator;
        const invIds = this.dataset.invids ? this.dataset.invids.split(',') : [];
        showInvestigationModal(indicator, invIds);
      };
    });
  };

  const tabs = document.querySelectorAll('[data-ti]');
  tabs.forEach(btn => {
    btn.onclick = () => {
      tabs.forEach(b => b.classList.remove('primary'));
      btn.classList.add('primary');
      fillTable(btn.dataset.ti);
    };
  });

  fillTable('IP');
  bindCommon();
}

function geolocation(){view.innerHTML=shell("GeoLocation Intelligence","Approximate IP-associated geographic intelligence.");view.innerHTML+=`<div class="card">${cardHead("GLOBAL IP MAP")}<div class="map" style="height:500px"><div class="route" style="left:17%;top:48%;width:55%;transform:rotate(-8deg)"></div><div class="route" style="left:53%;top:48%;width:22%;transform:rotate(25deg)"></div><div class="node" style="left:16%;top:46%"></div><div class="node" style="left:70%;top:40%"></div><div class="node" style="left:74%;top:63%"></div><div class="node-label" style="left:13%;top:51%">OBSERVED NODE · 203.0.113.42</div><div class="node-label" style="left:67%;top:45%">MUMBAI · APPROXIMATE</div></div></div><div class="two-col section-gap"><div class="card">${cardHead("OBSERVED IP")}<div class="email-meta">${meta("IP","203.0.113.42")}${meta("Country","India")}${meta("Region","Maharashtra")}${meta("City","Mumbai")}${meta("ISP","DemoNet Communications")}${meta("ASN","AS12345")}</div></div><div class="card">${cardHead("NETWORK ATTRIBUTES")}<div class="email-meta">${meta("Hosting Provider","Example Cloud")}${meta("VPN","Unknown")}${meta("TOR","Possible")}${meta("Proxy","Detected")}</div><div class="notice" style="margin:0 14px 14px">IP geolocation provides approximate network-associated geographic information and does not establish an individual's physical location.</div></div></div>`}
function infrastructure(){view.innerHTML=shell("Infrastructure Correlation","Correlate email, sender, domain, IP, URL and campaign entities.");view.innerHTML+=`<div class="two-col"><div class="card">${cardHead("INFRASTRUCTURE GRAPH")}<div class="graph"><svg viewBox="0 0 700 450">${svgNode(110,220,"Email","EMAIL")}${svgNode(280,120,"Sender","SENDER")}${svgNode(280,320,"Domain","DOMAIN")}${svgNode(470,120,"IP","IP")}${svgNode(470,320,"URL","URL")}${svgNode(620,220,"Campaign","CAMPAIGN")}<g class="graph-connections" stroke-width="2"><line x1="135" y1="205" x2="255" y2="135"/><line x1="135" y1="235" x2="255" y2="305"/><line x1="305" y1="120" x2="445" y2="120"/><line x1="305" y1="320" x2="445" y2="320"/><line x1="495" y1="135" x2="595" y2="205"/><line x1="495" y1="305" x2="595" y2="235"/></g></svg></div></div><div class="card">${cardHead("SELECTED ENTITY","<span class='badge high'></span>")}<div class="entity-panel"><span class="muted" style="font-size:8px">TYPE</span><div>Domain</div><div class="entity-value">example-login.com</div><div class="rel-grid"><div class="rel"><b>2</b><span>IPs</span></div><div class="rel"><b>4</b><span>URLs</span></div><div class="rel"><b>3</b><span>Cases</span></div><div class="rel"><b>1</b><span>Campaign</span></div></div><div class="notice" style="margin-top:14px">Relationships are simulated demo correlations and are not real-world attribution.</div></div></div></div>`}
function forensicReports(){view.innerHTML=shell("Forensic Reports","Generate, review and export investigation reports.",`<button class="btn primary" data-toast="PDF generation will be connected to the backend in the next development stage.">Generate Report</button>`);view.innerHTML+=`<div class="card">${cardHead("REPORT MANAGEMENT")}<div class="table-wrap"><table class="table"><thead><tr><th>REPORT ID</th><th>CASE ID</th><th>CLASSIFICATION</th><th>RISK</th><th>GENERATED</th><th>ANALYST</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody><tr><td>REPORT-12345</td><td>CASE-001</td><td>PHISHING / IMPERSONATION</td><td>${badge("CRITICAL")}</td><td>31 Aug 20:42</td><td>Security Analyst</td><td>READY</td><td><button class="btn" onclick="location.hash='report/12345'">Open</button></td></tr><tr><td>REPORT-12344</td><td>CASE-002</td><td>PHISHING</td><td>${badge("HIGH")}</td><td>31 Aug 20:18</td><td>Security Analyst</td><td>READY</td><td><button class="btn">Open</button></td></tr></tbody></table></div></div><div class="card section-gap">${cardHead("REPORT PREVIEW","<span class='badge low'></span>")}<div class="three-col" style="padding:15px">${["Case Information","Executive Summary","Email Information","AI Assessment","Header Analysis","IP Intelligence","GeoLocation","Threat Intelligence","Indicators of Compromise","Timeline","Evidence Integrity"].map(x=>`<div class="rel"><b>${x}</b><span>Included in report</span></div>`).join("")}</div><div style="padding:0 15px 15px"><button class="btn primary" data-toast="PDF generation will be connected to the backend in the next development stage.">Export PDF</button></div></div>`;bindCommon()}

function evidence(){
  simpleTable("Evidence","Preserve evidence metadata and verify cryptographic integrity.",["EVIDENCE ID","CASE ID","SHA-256","TIMESTAMP","SQL","VERIFICATION","ACTION"],[["EV-001","CASE-001","9f4d7e2b...d1a93f","20:42:18","REGISTERED","VERIFIED","Verify"],["EV-002","CASE-002","a81e21c9...98f02d","20:18:04","REGISTERED","VERIFIED","Verify"],["EV-003","CASE-003","c7210ab1...4f19ac","19:55:40","PENDING","REVIEW","Register"]],"Register Evidence");
  view.innerHTML+=`<div class="card section-gap">${cardHead("AI BOT EMAIL VISIT — SCREENSHOT EVIDENCE","<span class='badge verified'></span>")}<div style="padding:15px"><div class="email-meta" style="padding:0 0 14px">${meta("Evidence ID","EV-001")}${meta("Case ID","CASE-001")}${meta("Visited By","AI Forensic Bot v1")}${meta("Captured At","2026-08-31 20:42:31 IST")}${meta("Target Sender","alerts@sbi-corp-demo.test")}${meta("Screenshot Hash","b7c1e9a4...f30d2c")}</div><div style="border:1px solid #23364f;border-radius:9px;overflow:hidden;background:#0a1524"><div style="display:flex;align-items:center;gap:8px;padding:9px 12px;background:#0d1a2c;border-bottom:1px solid #1c2b40"><span style="width:9px;height:9px;border-radius:50%;background:#f05252;display:inline-block"></span><span style="width:9px;height:9px;border-radius:50%;background:#facc15;display:inline-block"></span><span style="width:9px;height:9px;border-radius:50%;background:#34d399;display:inline-block"></span><span style="margin-left:8px;font:9px 'JetBrains Mono';color:#7c8fa8">alerts@sbi-corp-demo.test — Sandboxed Inbox Preview</span></div><div style="padding:22px;background:#f7f9fc;color:#1d2735"><div style="font-size:11px;color:#8a94a3;margin-bottom:10px">From: <b style="color:#1d2735">SBI Corporate Banking Team</b> &lt;alerts@sbi-corp-demo.test&gt;</div><div style="font-size:13px;font-weight:700;margin-bottom:14px">Urgent Corporate Invoice Verification Required</div><p style="font-size:11px;line-height:1.7;margin:0 0 14px">Dear Finance Team,<br><br>Your SBI corporate banking invoice requires immediate verification.<br><br>Failure to complete the verification process within 2 hours may result in temporary suspension of your corporate payment account.</p><button disabled style="padding:9px 16px;background:#1769aa;color:#fff;border:0;border-radius:5px;font-size:10px">Verify Now</button></div></div><div class="notice" style="margin-top:12px">This screenshot is an automated, sandboxed AI-bot capture of the suspicious email content for evidentiary purposes. No live links were clicked and no external network connection was made by the analyst.</div></div></div>`;
  bindCommon();
}

function alerts(){view.innerHTML=shell("Security Alerts","Triage, investigate and resolve simulated security alerts.");view.innerHTML+=`<div class="card"><div style="padding:13px;display:grid;grid-template-columns:repeat(4,1fr);gap:8px"><select id="afSeverity" class="field"><option>All Severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select><select id="afStatus" class="field"><option>All Status</option><option>OPEN</option><option>RESOLVED</option></select><select id="afType" class="field"><option>All Type</option><option>Header Forensics</option><option>Authentication</option><option>URL Analysis</option><option>GeoLocation</option><option>AI Assessment</option><option>Correlation</option></select><input id="afDate" class="field" type="date"></div><div class="table-wrap"><table class="table"><thead><tr><th>ALERT</th><th>SEVERITY</th><th>CASE</th><th>SOURCE</th><th>TIME</th><th>STATUS</th><th>ACTION</th></tr></thead><tbody id="alertRows"></tbody></table></div></div>`;const data=demo.alerts.map((a,i)=>({a:a[0],sev:a[1],case:a[2],src:a[3],time:"20:"+(42-i*4),status:"OPEN",type:a[3]}));function fill(){const s=document.getElementById("afSeverity").value,st=document.getElementById("afStatus").value,t=document.getElementById("afType").value;document.getElementById("alertRows").innerHTML=data.filter(x=>(s==="All Severity"||x.sev===s)&&(st==="All Status"||x.status===st)&&(t==="All Type"||x.type===t)).map((x,i)=>`<tr><td>${x.a}</td><td>${badge(x.sev)}</td><td>${x.case}</td><td>${x.src}</td><td>${x.time}</td><td><span class="alert-status">${x.status}</span></td><td><button class="btn" onclick="location.hash='investigations/001'">Investigate</button> <button class="btn success" data-resolve="${i}">Mark Resolved</button></td></tr>`).join("");document.querySelectorAll("[data-resolve]").forEach(b=>b.onclick=()=>{const x=data[+b.dataset.resolve];x.status="RESOLVED";fill();toast("Alert marked resolved in demo mode.")})} ["afSeverity","afStatus","afType","afDate"].forEach(id=>document.getElementById(id).onchange=fill);fill();bindCommon()}
function settings(){view.innerHTML=shell("Settings","Configure account, security, privacy, notifications, retention and system integrations.");view.innerHTML+=`<div class="two-col"><div class="card">${cardHead("ACCOUNT")}<div class="form-grid"><div class="field"><label>Display Name</label><input value="Security Analyst"></div><div class="field"><label>Role</label><input value="Analyst" disabled></div><div class="field full"><label>Organization</label><input value="AICTE Cyber Security Cell — Demo Environment"></div></div></div><div class="card">${cardHead("SECURITY")}<div class="toggle">Two-Factor Authentication <span class="switch on"></span></div><div class="toggle">Session Timeout <span class="muted">30 minutes</span></div><div class="toggle">Audit Logging <span class="switch on"></span></div><div class="toggle">Login Notifications <span class="switch on"></span></div></div></div><div class="two-col section-gap"><div class="card">${cardHead("PRIVACY & EVIDENCE RETENTION")}<div class="toggle">Data Masking <span class="switch on"></span></div><div class="toggle">Evidence Retention <select><option>90 Days</option><option>180 Days</option><option>365 Days</option></select></div><div class="toggle">PII Redaction <span class="switch on"></span></div></div><div class="card">${cardHead("NOTIFICATIONS")}<div class="toggle">Email Alerts <span class="switch on"></span></div><div class="toggle">Browser Alerts <span class="switch on"></span></div><div class="toggle">High Risk Alerts <span class="switch on"></span></div><div class="toggle">Campaign Alerts <span class="switch on"></span></div></div></div><div class="card section-gap">${cardHead("SYSTEM CONFIGURATION")}<div class="list"><div class="toggle">VirusTotal <span class="badge low">NOT CONNECTED</span></div><div class="toggle">AbuseIPDB <span class="badge low">NOT CONNECTED</span></div><div class="toggle">GeoIP <span class="badge low">NOT CONNECTED</span></div><div class="toggle">Blockchain <span class="badge medium">DEVELOPMENT MODE</span></div><div class="toggle">AI Engine <span class="badge low">DEMO ENGINE</span></div><div class="toggle">Email Parser <span class="badge low">DEMO PARSER</span></div></div></div><div class="card section-gap">${cardHead("SECURITY UX NOTICE")}<div style="padding:15px"><div class="notice">Emails are untrusted evidence. Do not open suspicious attachments or directly visit suspicious URLs. IP geolocation is approximate. AI results require analyst review. Threat intelligence depends on external providers. Blockchain provides tamper-evident integrity records, not proof of evidence authenticity.</div></div></div>`;bindCommon()}

function getGeoForIP(ip) {
  const map = {
    '203.0.113.42': { Country: 'India', Region: 'Maharashtra', City: 'Mumbai', ISP: 'DemoNet Communications', ASN: 'AS12345' },
    '198.51.100.24': { Country: 'India', Region: 'Maharashtra', City: 'Mumbai', ISP: 'Example Cloud', ASN: 'AS67890' },
    '192.0.2.1': { Country: 'United States', Region: 'California', City: 'Los Angeles', ISP: 'Demo ISP', ASN: 'AS11111' }
  };
  return map[ip] || { Country: 'Unknown', Region: '—', City: '—', ISP: '—', ASN: '—' };
}

function investigationDetail() {
  const hashParts = location.hash.slice(1).split('/');
  const id = decodeURIComponent(hashParts[1] || '');
  const d = (SM.state.scans || []).find(x => x.id === id);
  if (!d) {
    view.innerHTML = shell(
      "Investigation Not Found",
      "Open an investigation from the uploaded email investigations list.",
      `<button class="btn primary" onclick="location.hash='investigations'">Back to Investigations</button>`
    );
    view.innerHTML += `<div class="card"><div class="empty"><strong>No matching investigation</strong><p class="muted">This investigation does not exist in the browser's local records.</p></div></div>`;
    bindCommon();
    return;
  }

  view.innerHTML = shell(
    d.id,
    `Risk ${Number(d.score || 0)}/100 · Classification ${SM.esc(d.classification || 'ANALYZED')} · Uploaded ${SM.esc(d.time || '—')}`,
    `<button class="btn" onclick="location.hash='email-analysis'">Back to Email Analysis</button>`
  );

  view.insertAdjacentHTML(
    'beforeend',
    `<div class="card section-gap"><div class="card-head"><span class="card-title">INVESTIGATION SUMMARY</span><span class="badge ${String(d.risk || 'LOW').toLowerCase()}">${SM.esc(d.risk || 'LOW')}</span></div>
    <div class="email-meta">
      ${meta("Investigation ID", SM.esc(d.id))}
      ${meta("Risk Score", `${Number(d.score || 0)}/100`)}
      ${meta("Classification", SM.esc(d.classification || "ANALYZED"))}
      ${meta("File", SM.esc(d.fileName || "—"))}
      ${meta("Sender", SM.esc(d.from || "—"))}
      ${meta("Subject", SM.esc(d.subject || "—"))}
    </div></div>`
  );

  const tabNames = [
    { key: 'overview', label: 'Overview' },
    { key: 'email-evidence', label: 'Email Evidence' },
    { key: 'header-forensics', label: 'Header Forensics' },
    { key: 'threat-intel', label: 'Threat Intelligence' },
    { key: 'geolocation', label: 'GeoLocation' },
    { key: 'infrastructure', label: 'Infrastructure' },
    { key: 'timeline', label: 'Timeline' },
    { key: 'evidence', label: 'Evidence' },
    { key: 'report', label: 'Report' },
    { key: 'all-data', label: 'All Data' }
  ];

  let tabsHtml = `<div class="card section-gap investigation-detail-card"><div class="tabs" style="display:flex;gap:4px;padding:10px;border-bottom:1px solid var(--border);flex-wrap:wrap">`;
  tabNames.forEach((t, i) => {
    tabsHtml += `<button class="btn ${i === 0 ? 'primary' : ''}" data-tab="${t.key}">${t.label}</button>`;
  });
  tabsHtml += `</div><div class="tab-content" style="padding:12px 16px;">`;

  const panes = {
    overview: () => `
      <div class="result-header" style="padding:0 0 12px 0;">
        <div><span class="badge ${d.risk.toLowerCase()}">THREAT LEVEL · ${d.risk}</span>
        <h2 style="font-size:18px;margin:10px 0 4px">${SM.esc(d.classification)}</h2>
        <p class="muted" style="font-size:10px">Evidence‑based local assessment. External reputation and ML services are not queried.</p></div>
        <div style="text-align:right"><div class="risk-score">${d.score}/100</div><span class="muted" style="font-size:9px">LOCAL EVIDENCE SCORE</span></div>
      </div>
      <div class="tactics">${(d.reasons || []).slice(0, 6).map(r => `<span class="tactic">${SM.esc(r.toUpperCase())}</span>`).join('')}</div>
      <div style="margin-top:12px;">
        <div class="stat-row"><span>Sender Domain <b>${SM.esc(d.fromDomain || '—')}</b></span>
        <span>Reply‑To Domain <b>${SM.esc(d.replyDomain || '—')}</b></span>
        <span>Return‑Path Domain <b>${SM.esc(d.returnDomain || '—')}</b></span></div>
      </div>
    `,
    'email-evidence': () => `
      <div class="email-meta" style="padding:0;">
        ${meta("From", SM.esc(d.from))}
        ${meta("To", SM.esc(d.to))}
        ${meta("Subject", SM.esc(d.subject))}
        ${meta("Date", SM.esc(d.date))}
        ${meta("Message-ID", SM.esc(d.messageId))}
        ${meta("Reply-To", SM.esc(d.reply || '—'))}
        ${meta("Return-Path", SM.esc(d.returnPath || '—'))}
      </div>
    `,
    'header-forensics': () => `
      <div class="auth-grid">${authDynamic("SPF", d.spf)}${authDynamic("DKIM", d.dkim)}${authDynamic("DMARC", d.dmarc)}</div>
      <div style="margin-top:12px;"><details><summary style="padding:10px;cursor:pointer;color:#9db0c5;font-size:10px">VIEW RAW HEADERS</summary><pre class="code">${SM.esc(d.raw || '')}</pre></details></div>
      <div class="email-meta" style="padding:12px 0 0;">
        ${meta("Received Hops", String(d.received?.length || 0))}
      </div>
    `,
    'threat-intel': () => `
      <div class="email-meta" style="padding:0;">
        ${meta("IPs", (d.ips || []).length ? d.ips.map(SM.esc).join(', ') : 'None found')}
        ${meta("URLs", (d.urls || []).length ? d.urls.map(u => `<a href="#" style="color:var(--cyan);text-decoration:none;" onclick="event.preventDefault();toast('URL analysis (simulated)')">${SM.esc(u)}</a>`).join('<br>') : 'None found')}
        ${meta("File SHA-256", SM.esc(d.hash || '—'))}
      </div>
      <div class="notice" style="margin-top:12px;">Threat intelligence is simulated. Real integration would query external APIs.</div>
    `,
    geolocation: () => {
      const ip = (d.ips && d.ips.length) ? d.ips[0] : null;
      let geoHtml = `<div class="email-meta" style="padding:0;">${meta("Observed IP", SM.esc(ip || 'None'))}</div>`;
      if (ip) {
        const geo = getGeoForIP(ip);
        geoHtml += `<div class="email-meta" style="padding:12px 0 0;">${Object.entries(geo).map(([k,v]) => meta(k, v)).join('')}</div>`;
        geoHtml += `<div class="notice" style="margin-top:12px;">IP geolocation is approximate and does not identify an individual's physical location.</div>`;
      } else {
        geoHtml += `<div class="empty"><p class="muted">No IP address extracted from this email.</p></div>`;
      }
      return geoHtml;
    },
    infrastructure: () => `
      <div class="graph" style="height:300px;">
        <svg viewBox="0 0 700 450">
          ${svgNode(110,220,"Email","EMAIL")}
          ${svgNode(280,120,"Sender","SENDER")}
          ${svgNode(280,320,"Domain","DOMAIN")}
          ${svgNode(470,120,"IP","IP")}
          ${svgNode(470,320,"URL","URL")}
          ${svgNode(620,220,"Campaign","CAMPAIGN")}
          <g class="graph-connections" stroke-width="2">
            <line x1="135" y1="205" x2="255" y2="135"/>
            <line x1="135" y1="235" x2="255" y2="305"/>
            <line x1="305" y1="120" x2="445" y2="120"/>
            <line x1="305" y1="320" x2="445" y2="320"/>
            <line x1="495" y1="135" x2="595" y2="205"/>
            <line x1="495" y1="305" x2="595" y2="235"/>
          </g>
        </svg>
      </div>
      <div class="notice" style="margin-top:12px;">Relationships are simulated demo correlations and are not real‑world attribution.</div>
    `,
    timeline: () => {
      const received = d.received || [];
      if (!received.length) return `<div class="empty"><p class="muted">No received headers available.</p></div>`;
      return `<div class="timeline">${received.map((r, i) => `
        <div class="timeline-item">
          <div class="timeline-time">${i + 1}</div>
          <div class="timeline-line"></div>
          <div class="timeline-body"><strong>Hop ${i + 1}</strong><p>${SM.esc(r)}</p></div>
        </div>
      `).join('')}</div>`;
    },
    evidence: () => `
      <div class="email-meta" style="padding:0;">
        ${meta("File Name", SM.esc(d.fileName || '—'))}
        ${meta("File Size", SM.fmtBytes(d.size || 0))}
        ${meta("SHA-256", SM.esc(d.hash || '—'))}
        ${meta("Uploaded", SM.esc(d.time || '—'))}
      </div>
      <div style="margin-top:12px;"><button class="btn success" onclick="toast('Evidence cryptographically verified — zero tampering detected.')">Verify Integrity</button></div>
      <div class="notice" style="margin-top:12px;">Blockchain provides tamper‑evident integrity records, not proof of evidence authenticity.</div>
      <div class="card section-gap" style="margin-top:14px;">${cardHead("AI BOT EMAIL VISIT — SCREENSHOT EVIDENCE","<span class='badge verified'></span>")}<div style="padding:15px"><div class="email-meta" style="padding:0 0 14px">${meta("Evidence ID", SM.esc(d.id || "EV-001"))}${meta("Target Sender", SM.esc(d.from || "alerts@sbi-corp-demo.test"))}${meta("Screenshot Hash", SM.esc(d.hash ? d.hash.slice(0,16)+"...": "b7c1e9a4...f30d2c"))}</div><div style="border:1px solid #23364f;border-radius:9px;overflow:hidden;background:#0a1524"><div style="display:flex;align-items:center;gap:8px;padding:9px 12px;background:#0d1a2c;border-bottom:1px solid #1c2b40"><span style="width:9px;height:9px;border-radius:50%;background:#f05252;display:inline-block"></span><span style="width:9px;height:9px;border-radius:50%;background:#facc15;display:inline-block"></span><span style="width:9px;height:9px;border-radius:50%;background:#34d399;display:inline-block"></span><span style="margin-left:8px;font:9px 'JetBrains Mono';color:#7c8fa8">${SM.esc(d.from || "alerts@sbi-corp-demo.test")} — Sandboxed Inbox Preview</span></div><div style="padding:22px;background:#f7f9fc;color:#1d2735"><div style="font-size:11px;color:#8a94a3;margin-bottom:10px">From: <b style="color:#1d2735">${SM.esc(d.from || "SBI Corporate Banking Team")}</b></div><div style="font-size:13px;font-weight:700;margin-bottom:14px">${SM.esc(d.subject || "Urgent Corporate Invoice Verification Required")}</div><p style="font-size:11px;line-height:1.7;margin:0 0 14px">${SM.esc(d.subject || "Your corporate banking invoice requires immediate verification.")}<br><br>Automated sandboxed rendering of captured evidence.</p><button disabled style="padding:9px 16px;background:#1769aa;color:#fff;border:0;border-radius:5px;font-size:10px">Verify Now</button></div></div><div class="notice" style="margin-top:12px">This screenshot is an automated, sandboxed AI-bot capture of the suspicious email content for evidentiary purposes.</div></div></div>
    `,
    report: () => `
      <div class="three-col" style="padding:0;">
        ${["Case Information","Executive Summary","Email Information","AI Assessment","Header Analysis","IP Intelligence","GeoLocation","Threat Intelligence","Indicators of Compromise","Timeline","Evidence Integrity"].map(x => `<div class="rel"><b>${x}</b><span>Included in report</span></div>`).join('')}
      </div>
      <div style="margin-top:12px;display:flex;gap:8px;">
        <button class="btn primary" onclick="toast('PDF generation will be connected to the backend in the next development stage.')">Generate PDF</button>
        <button class="btn" onclick="window.print()">Print Report</button>
      </div>
    `,
    'all-data': () => {
      const exclude = ['raw', 'rawFull'];
      const fields = Object.keys(d).filter(k => !exclude.includes(k) && k !== 'rawFull');
      let html = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">`;
      fields.forEach(key => {
        let value = d[key];
        if (Array.isArray(value)) value = value.join(', ');
        else if (typeof value === 'object') value = JSON.stringify(value);
        else value = String(value ?? '—');
        html += `<div class="meta"><label>${SM.esc(key)}</label><span>${SM.esc(value)}</span></div>`;
      });
      html += `</div>`;
      html += `<hr style="border-color:var(--border);margin:16px 0;">`;
      html += `<details><summary style="cursor:pointer;color:var(--cyan);font-weight:600;">📄 RAW HEADERS</summary><pre class="code" style="max-height:300px;overflow:auto;">${SM.esc(d.raw || '')}</pre></details>`;
      if (d.rawFull) {
        html += `<details style="margin-top:10px;"><summary style="cursor:pointer;color:var(--cyan);font-weight:600;">📄 FULL RAW EMAIL (Headers + Body)</summary><pre class="code" style="max-height:400px;overflow:auto;">${SM.esc(d.rawFull)}</pre></details>`;
      }
      return html;
    }
  };

  tabNames.forEach(t => {
    const content = panes[t.key] ? panes[t.key]() : `<div class="empty"><p>Tab content not implemented.</p></div>`;
    const active = t.key === 'overview' ? ' active' : '';
    tabsHtml += `<div class="tab-pane${active}" data-tab="${t.key}" style="${t.key !== 'overview' ? 'display:none;' : ''}">${content}</div>`;
  });

  tabsHtml += `</div></div>`;
  view.insertAdjacentHTML('beforeend', tabsHtml);

  const tabsContainer = document.querySelector('.investigation-detail-card');
  if (tabsContainer) {
    const btns = tabsContainer.querySelectorAll('.tabs .btn');
    const panes = tabsContainer.querySelectorAll('.tab-pane');
    btns.forEach(btn => {
      btn.addEventListener('click', function() {
        const tabKey = this.dataset.tab;
        btns.forEach(b => b.classList.remove('primary'));
        this.classList.add('primary');
        panes.forEach(p => {
          if (p.dataset.tab === tabKey) {
            p.style.display = 'block';
            p.classList.add('active');
          } else {
            p.style.display = 'none';
            p.classList.remove('active');
          }
        });
      });
    });
  }

  bindCommon();
}

function render(){let hash=location.hash.slice(1)||"dashboard",parts=hash.split("/"),route=parts[0];document.querySelectorAll("#nav a").forEach(a=>a.classList.toggle("active",a.dataset.route===route));pageCrumb.textContent=(routes[route]||"FORENSIC REPORT").toUpperCase();document.getElementById("sidebar").classList.remove("open");if(route==="dashboard")dashboard();else if(route==="email-analysis")emailAnalysis();else if(route==="investigations"&&parts[1])investigationDetail();else if(route==="investigations")investigations();else if(route==="threat-intelligence")threatIntel();else if(route==="geolocation")geolocation();else if(route==="infrastructure")infrastructure();else if(route==="forensic-reports")forensicReports();else if(route==="evidence")evidence();else if(route==="alerts")alerts();else if(route==="settings")settings();else if(route==="report")report(parts[1]||"12345");else home()}
window.addEventListener("hashchange",render);document.getElementById("menuBtn").onclick=()=>document.getElementById("sidebar").classList.toggle("open");document.getElementById("globalSearch").onkeydown=e=>{if(e.key==="Enter"){const q=e.target.value.trim();if(q)toast(`No local match for “${q}”`)}};

function initTheme() {
  const savedTheme = localStorage.getItem("sentinelmail_theme") || "light";
  document.documentElement.setAttribute("data-theme", savedTheme);
  updateThemeIcon(savedTheme);

  const toggleBtn = document.getElementById("themeToggle");
  if (toggleBtn) {
    toggleBtn.onclick = () => {
      const current = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
      const next = current === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("sentinelmail_theme", next);
      updateThemeIcon(next);

      const route = location.hash.slice(1).split('/')[0] || "dashboard";
      if (route === "dashboard") {
        renderCharts();
      }

      toast(`Switched to ${next} mode`);
    };
  }
}

function updateThemeIcon(theme) {
  const toggleBtn = document.getElementById("themeToggle");
  if (toggleBtn) {
    toggleBtn.innerHTML = theme === "dark" ? "☀️" : "🌙";
    toggleBtn.title = theme === "dark" ? "Switch to Light Mode" : "Switch to Dark Mode";
  }
}

const SM = {
  key: "sentinelmail_state_v2",
  state: JSON.parse(localStorage.getItem("sentinelmail_state_v2") || "null") || { scans: [], cases: [], settings: {} },
  save(){ localStorage.setItem(this.key, JSON.stringify(this.state)); },
  esc(v){ return String(v ?? "").replace(/[&<>\"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c])); },
  fmtBytes(n){ if(n<1024) return `${n} B`; if(n<1048576) return `${(n/1024).toFixed(1)} KB`; return `${(n/1048576).toFixed(2)} MB`; },
  now(){ return new Date().toLocaleTimeString([], {hour:"2-digit", minute:"2-digit", second:"2-digit"}); },
  async hash(text){ const buf=await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)); return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,"0")).join(""); },
  headers(raw){
    const head=raw.split(/\r?\n\r?\n/)[0] || "";
    const lines=head.replace(/\r/g,"").split("\n");
    const unfolded=[]; for(const line of lines){ if(/^[ \t]/.test(line) && unfolded.length) unfolded[unfolded.length-1]+=" "+line.trim(); else unfolded.push(line); }
    const out={}; for(const line of unfolded){ const i=line.indexOf(":"); if(i>0){ const k=line.slice(0,i).trim().toLowerCase(); if(out[k]) out[k]+="\n"+line.slice(i+1).trim(); else out[k]=line.slice(i+1).trim(); } }
    return {head, map:out};
  },
  addr(v){ const m=String(v||"").match(/<([^>]+)>|([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})/); return m ? (m[1]||m[2]) : String(v||""); },
  domain(v){ const a=this.addr(v); return a.includes("@") ? a.split("@").pop().toLowerCase() : ""; },
  analyze(raw, file, hash) {
    const { head, map } = this.headers(raw);
    const from = this.addr(map.from);
    const reply = this.addr(map["reply-to"]);
    const returnPath = this.addr(map["return-path"]);
    const fromDomain = this.domain(map.from);
    const replyDomain = this.domain(map["reply-to"]);
    const returnDomain = this.domain(map["return-path"]);
    const urls = [...raw.matchAll(/https?:\/\/[^\s<>"']+/gi)].map(m => m[0].replace(/[),.;]+$/, ""));
    const ips = [...new Set((raw.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
    const received = (map.received || "").split("\n").filter(Boolean);

    const authResults = [...head.matchAll(/authentication-results:[^\n]*(?:\n[ \t]+[^\n]*)*/gi)].map(m => m[0]).join(" ");
    const authSource = authResults || head;
    const getAuth = (name) => {
      const m = authSource.match(new RegExp('\\b' + name + '\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)\\b', 'i'));
      return m ? m[1].toUpperCase() : "UNKNOWN";
    };
    const spf = getAuth("spf");
    const dkim = getAuth("dkim");
    const dmarc = getAuth("dmarc");

    let score = 0, reasons = [];
    const add = (points, reason) => { score += points; reasons.push(reason); };
    if (spf === "FAIL" || spf === "SOFTFAIL") add(spf === "FAIL" ? 22 : 14, `SPF ${spf.toLowerCase()}`);
    if (dkim === "FAIL") add(24, "DKIM failure");
    if (dmarc === "FAIL") add(30, "DMARC failure");
    if (fromDomain && replyDomain && fromDomain !== replyDomain) add(12, "Reply-To domain differs from sender");
    if (fromDomain && returnDomain && fromDomain !== returnDomain) add(7, "Return-Path domain differs from sender");

    const suspiciousUrls = urls.filter(u => {
      try {
        const host = new URL(u).hostname.toLowerCase();
        return /xn--/.test(host) || /@/.test(u.split('://')[1] || '') ||
          /(?:bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rebrand\.ly)$/i.test(host) ||
          /(?:login|signin|verify|password|credential|account|payment|invoice|secure)/i.test(u);
      } catch { return false; }
    });
    if (suspiciousUrls.length) add(Math.min(15, suspiciousUrls.length * 5), `${suspiciousUrls.length} suspicious URL${suspiciousUrls.length > 1 ? 's' : ''}`);

    const subjectAndBody = `${map.subject || ""} ${raw.slice(raw.indexOf('\n\n') + 2, raw.indexOf('\n\n') + 12002)}`;
    const socialTerms = (subjectAndBody.match(/\b(urgent|verify|password|credential|reset|account suspended|payment required|invoice due|action required|confirm your account)\b/gi) || []).length;
    if (socialTerms >= 2) add(8, "Multiple social-engineering indicators");

    const dangerousAttachment = /content-type:[^\n]*name=["']?[^\n"']+\.(exe|scr|js|vbs|cmd|bat|ps1|jar|msi|iso|img|lnk|hta)\b/i.test(head) ||
      /content-disposition:[^\n]*filename=["']?[^\n"']+\.(exe|scr|js|vbs|cmd|bat|ps1|jar|msi|iso|img|lnk|hta)\b/i.test(head);
    if (dangerousAttachment) add(15, "Potentially dangerous attachment type");

    score = Math.max(0, Math.min(100, score));
    const risk = score >= 75 ? "CRITICAL" : score >= 50 ? "HIGH" : score >= 25 ? "MEDIUM" : "LOW";
    const classification = score >= 75 ? "PHISHING" : score >= 50 ? "SUSPICIOUS" : score >= 25 ? "REVIEW" : "LIKELY LEGITIMATE";
    if (!reasons.length) reasons.push("No high-confidence suspicious indicators found");

    return {
      id: `INV-${Date.now().toString().slice(-6)}`,
      fileName: file.name,
      size: file.size,
      hash,
      time: this.now(),
      from,
      reply,
      returnPath,
      fromDomain,
      replyDomain,
      returnDomain,
      to: map.to || "—",
      subject: map.subject || "(No subject)",
      date: map.date || "—",
      messageId: map["message-id"] || "—",
      spf,
      dkim,
      dmarc,
      urls,
      ips,
      received,
      score,
      risk,
      classification,
      reasons,
      raw: head,
      rawFull: raw,
      suspiciousUrls
    };
  }
};

function authDynamic(name,value){ const cls=value==="PASS"?"pass":value==="FAIL"?"fail":"warning"; return `<div class="auth"><b>${name}</b><strong class="${cls}">● ${value}</strong><span class="muted" style="font-size:8px">Browser-side assessment</span></div>`; }
function resultSummaryDynamic(d){ return `<div class="result-header" style="padding:0"><div><span class="badge ${d.risk.toLowerCase()}">THREAT LEVEL · ${d.risk}</span><h2 style="font-size:18px;margin:10px 0 4px">${SM.esc(d.classification)}</h2><p class="muted" style="font-size:10px">Evidence-based local assessment. External reputation and ML services are not queried.</p></div><div style="text-align:right"><div class="risk-score">${d.score}/100</div><span class="muted" style="font-size:9px">LOCAL EVIDENCE SCORE</span></div></div><div class="tactics">${d.reasons.slice(0,6).map(x=>`<span class="tactic">${SM.esc(x.toUpperCase())}</span>`).join("")}</div>`; }

function emailAnalysis(){
  const latest=SM.state.scans[0];
  view.innerHTML=shell("Email Threat Analysis","Inspect an .EML file locally and turn its headers into an investigation record.");
  view.innerHTML+=`<div class="two-col"><div class="card"><div class="upload" id="drop"><div class="upload-icon">⇧</div><h3>DROP .EML FILE HERE</h3><p>OR</p><button class="btn primary" id="browse">Browse Files</button><p>Supported format: .EML · Maximum size: 25 MB</p><input id="fileInput" type="file" accept=".eml,message/rfc822" class="hidden"></div><div id="fileInfo" class="hidden"></div></div><div class="card analysis-result-card">${cardHead("ANALYSIS RESULT")}<div id="resultBox" style="padding:15px">${latest?resultSummaryDynamic(latest):`<div class="empty"><strong>No email analyzed yet</strong><p class="muted">Choose an .EML file to start a local forensic inspection.</p></div>`}</div></div></div>`;
  if(latest) renderAnalysisDetails(latest); else renderAnalysisDetails({spf:"UNKNOWN",dkim:"UNKNOWN",dmarc:"UNKNOWN",from:"—",to:"—",subject:"—",reply:"—",returnPath:"—",messageId:"—",raw:"No email loaded.",ips:[],urls:[],hash:"—",received:[]});
  bindUpload();
}
function renderAnalysisDetails(d){
  view.insertAdjacentHTML("beforeend", `<div class="card section-gap">${cardHead("HEADER FORENSICS")}<div class="auth-grid">${authDynamic("SPF",d.spf)}${authDynamic("DKIM",d.dkim)}${authDynamic("DMARC",d.dmarc)}</div><div class="email-meta">${meta("From",SM.esc(d.from))}${meta("To",SM.esc(d.to))}${meta("Subject",SM.esc(d.subject))}${meta("Reply-To",SM.esc(d.reply||"—"))}${meta("Return-Path",SM.esc(d.returnPath||"—"))}${meta("Message-ID",SM.esc(d.messageId||"—"))}</div></div><div class="card section-gap">${cardHead("OBSERVED INDICATORS")}<div class="email-meta">${meta("IP Addresses",d.ips?.length?d.ips.map(SM.esc).join(", "):"None found")}${meta("URLs",d.urls?.length?d.urls.map(SM.esc).join("<br>"):"None found")}${meta("File SHA-256",SM.esc(d.hash||"—"))}${meta("Received Hops",String(d.received?.length||0))}</div></div><div class="card section-gap">${cardHead("RAW EMAIL HEADERS")}<details><summary style="padding:13px 15px;cursor:pointer;color:#9db0c5;font-size:10px">VIEW RAW HEADERS</summary><pre class="code">${SM.esc(d.raw||"")}</pre></details></div>`);
}
function bindUpload(){
  const inp=document.getElementById("fileInput"),browse=document.getElementById("browse"),drop=document.getElementById("drop"); if(!inp||!browse||!drop)return;
  browse.onclick=()=>inp.click(); inp.onchange=()=>{if(inp.files[0])showFile(inp.files[0])};
  drop.ondragover=e=>{e.preventDefault();drop.style.borderColor="var(--cyan)"}; drop.ondragleave=()=>drop.style.borderColor="";
  drop.ondrop=e=>{e.preventDefault();drop.style.borderColor="";const f=e.dataTransfer.files[0];if(f)showFile(f)};
}
async function showFile(f){
  const info=document.getElementById("fileInfo"); if(!info)return;
  if(!/\.eml$/i.test(f.name) && f.type!=="message/rfc822"){toast("Please select an .EML file.");return;}
  if(f.size>25*1024*1024){toast("File is larger than the 25 MB frontend limit.");return;}
  info.classList.remove("hidden"); info.innerHTML=`<div style="padding:13px;border-top:1px solid var(--border)"><b style="font-size:10px">${SM.esc(f.name)}</b><span class="muted" style="font-size:9px;margin-left:8px">${SM.fmtBytes(f.size)}</span><span class="badge verified" style="float:right">LOADED</span><button class="btn primary" id="analyzeLocal" style="margin-top:10px;width:100%">Analyze Locally</button></div>`;
  document.getElementById("analyzeLocal").onclick=async()=>{
    const b=document.getElementById("analyzeLocal");b.disabled=true;b.textContent="Analyzing…";
    try{const raw=await f.text();const hash=await SM.hash(raw);const d=SM.analyze(raw,f,hash);SM.state.scans.unshift(d);SM.state.scans=SM.state.scans.slice(0,30);SM.save();toast(`Analysis complete · ${d.risk} · ${d.score}/100`);render();location.hash="email-analysis";}catch(e){console.error(e);toast("Could not read this EML file in the browser.");}
  };
}

const oldInvestigations=investigations;
investigations=function(){
  const scans=SM.state.scans || [];
  view.innerHTML=shell("Investigation Cases","Cases created from your uploaded email analyses.",`<button class="btn primary" id="createCase">＋ Create Investigation</button>`);
  view.innerHTML+=`<div class="card"><div style="padding:13px;display:flex;gap:8px;flex-wrap:wrap"><input class="field" id="caseSearch" placeholder="Search cases, sender, subject, domain..." style="background:#091523;border:1px solid #23364f;color:#dbe7f4;border-radius:6px;padding:9px;font:10px Inter;flex:1;min-width:180px"><select id="riskFilter" class="field"><option>All Risk</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select></div><div class="table-wrap"><table class="table"><thead><tr><th>CASE</th><th>TIME</th><th>SENDER</th><th>SUBJECT</th><th>CLASS</th><th>SCORE</th><th>RISK</th><th>ACTION</th></tr></thead><tbody id="caseRows"></tbody></table></div></div>`;
  function fill(){const q=(document.getElementById("caseSearch").value||"").toLowerCase(),r=document.getElementById("riskFilter").value;document.getElementById("caseRows").innerHTML=scans.filter(x=>(r==="All Risk"||x.risk===r)&&(!q||`${x.id} ${x.from} ${x.subject} ${x.fromDomain}`.toLowerCase().includes(q))).map(x=>`<tr><td>${SM.esc(x.id)}</td><td>${SM.esc(x.time)}</td><td>${SM.esc(x.from||"—")}</td><td>${SM.esc(x.subject||"—")}</td><td>${badge(x.classification||"ANALYZED")}</td><td>${x.score}%</td><td>${badge(x.risk)}</td><td><button class="btn" onclick="location.hash='investigations/${encodeURIComponent(x.id)}'">Open</button></td></tr>`).join("")||`<tr><td colspan="8" class="muted" style="padding:25px;text-align:center">No uploaded email investigations yet.</td></tr>`} document.getElementById("caseSearch").oninput=fill;document.getElementById("riskFilter").onchange=fill;fill();bindCommon();
};

document.getElementById("globalSearch").onkeydown=e=>{if(e.key!=="Enter")return;const q=e.target.value.trim().toLowerCase();if(!q)return;const scan=SM.state.scans.find(x=>`${x.id} ${x.from} ${x.subject} ${x.fromDomain}`.toLowerCase().includes(q));if(scan){location.hash=`report/${encodeURIComponent(scan.id)}`;e.target.value="";return;}if(/ip|domain|url|threat/.test(q))location.hash="threat-intelligence";else if(/case|investigation/.test(q))location.hash="investigations";else toast(`No local match for “${q}”`)};

const oldReport=report;
report=function(id){ oldReport(id); setTimeout(()=>{document.querySelectorAll("[data-print-report]").forEach(b=>b.onclick=()=>window.print())},0); };

const oldSettings=settings;
settings=function(){oldSettings();setTimeout(()=>{document.querySelectorAll(".switch").forEach((s,i)=>{const k=`switch_${i}`;const saved=localStorage.getItem(k);if(saved!==null)s.classList.toggle("on",saved==="1");s.addEventListener("click",()=>localStorage.setItem(k,s.classList.contains("on")?"1":"0"));});},0)};

initTheme();
if (!location.hash) location.hash = "dashboard";
render();
