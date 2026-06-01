import jsPDF from "jspdf";
import React from "react";
import { useState, useEffect, useRef } from "react";

const DEMO_TARGETS = {
  "malicious-domain.xyz": {
    type: "domain",
    whois: {
      registrar: "NameSilo, LLC",
      created: "2024-11-03",
      expires: "2025-11-03",
      registrant: "REDACTED FOR PRIVACY",
      country: "PA",
      nameservers: ["ns1.cloudflare.com", "ns2.cloudflare.com"],
    },
    indicators: [
      { type: "IP", value: "185.220.101.47", source: "DNS", risk: "high" },
      { type: "Domain", value: "malicious-domain.xyz", source: "WHOIS", risk: "high" },
      { type: "Domain", value: "login.malicious-domain.xyz", source: "Passive DNS", risk: "critical" },
      { type: "Email", value: "admin@protonmail.com", source: "WHOIS", risk: "medium" },
      { type: "ASN", value: "AS209100 (Tor Exit)", source: "IP Lookup", risk: "critical" },
    ],
    github: {
      source: "github", status: "success", verdict: "suspicious", confidence: "low",
      summary: "GitHub: 2 relevant result(s) out of 14 total (12 filtered as proxy lists or dumps).",
      raw: {
        total_count: 14, relevant_count: 2, filtered_count: 12,
        repos: [
          { name: "security-researcher/ioc-list", description: "Known phishing domains — malicious-domain.xyz confirmed active Nov 2024", url: "https://github.com/security-researcher/ioc-list", stars: 234, updated: "2024-11-10T12:00:00Z", topics: ["threat-intel", "ioc"], relevant: true },
          { name: "analyst/phishing-tracker", description: "Tracking active phishing infrastructure targeting corporate SSO portals", url: "https://github.com/analyst/phishing-tracker", stars: 45, updated: "2024-11-08T09:00:00Z", topics: ["phishing", "security"], relevant: true },
        ],
      },
    },
    riskScore: 87,
    narrative: `This domain presents a high-confidence phishing infrastructure profile. Registered November 2024 (age: ~6 months), it uses privacy-shielded WHOIS through a Panama registrar — a common pattern for disposable phishing domains. The associated IP (185.220.101.47) resolves to ASN AS209100, a known Tor exit node cluster frequently abused for credential harvesting operations.\n\nPassive DNS reveals a subdomain "login.malicious-domain.xyz," strongly suggesting credential phishing targeting corporate SSO or banking portals. Corroborating intelligence from OTX threat feeds and GitHub security repositories confirms active phishing campaigns.\n\nRecommendation: Block at DNS and email gateway layers. Flag ASN AS209100 for broader blocking. Submit to threat feeds for downstream propagation.`,
  },
  "192.168.1.100": {
    type: "ip",
    whois: {
      asn: "RFC1918 Private Range",
      org: "N/A — Private Address Space",
      country: "N/A",
      range: "192.168.0.0/16",
    },
    indicators: [
      { type: "IP", value: "192.168.1.100", source: "Input", risk: "low" },
    ],
    github: {
      source: "github", status: "not_found", verdict: "unknown", confidence: "low",
      summary: "Target not mentioned in any GitHub repository.",
      raw: { total_count: 0, relevant_count: 0, filtered_count: 0, repos: [] },
    },
    riskScore: 5,
    narrative: `192.168.1.100 falls within RFC1918 private address space (192.168.0.0/16) and is not routable on the public internet. No OSINT data is available for private IPs via public sources.\n\nThis target may be relevant in the context of internal network investigations, lateral movement analysis, or misconfigured asset discovery. Recommend pivoting to internal SIEM/EDR data for investigation.`,
  },
};

const STEPS = [
  { id: "whois", label: "WHOIS Lookup", icon: "🔍", duration: 1200 },
  { id: "dns", label: "Passive DNS Resolution", icon: "🌐", duration: 900 },
  { id: "github", label: "GitHub Intelligence", icon: "💻", duration: 1400 },
  { id: "threatfeeds", label: "Threat Feed Correlation", icon: "🎯", duration: 1000 },
  { id: "ioc", label: "IOC Aggregation", icon: "⚠️", duration: 600 },
  { id: "llm", label: "Generating AI Report", icon: "🤖", duration: 1800 },
];

const RISK_COLORS = {
  critical: { bg: "#ff2d2d22", text: "#ff4444", border: "#ff444444" },
  high: { bg: "#ff6b0022", text: "#ff8c42", border: "#ff8c4244" },
  medium: { bg: "#ffd70022", text: "#ffd700", border: "#ffd70044" },
  low: { bg: "#00ff8822", text: "#00e676", border: "#00e67644" },
};

function RiskBadge({ level }) {
  const c = RISK_COLORS[level] || RISK_COLORS.low;
  return (
    <span style={{
      background: c.bg, color: c.text, border: `1px solid ${c.border}`,
      borderRadius: "3px", padding: "2px 8px", fontSize: "11px",
      fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, letterSpacing: "0.05em",
      textTransform: "uppercase",
    }}>{level}</span>
  );
}

function ScoreMeter({ score }) {
  const color = score > 75 ? "#ff4444" : score > 50 ? "#ff8c42" : score > 25 ? "#ffd700" : "#00e676";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
      <div style={{ position: "relative", width: 80, height: 80 }}>
        <svg width="80" height="80" viewBox="0 0 80 80">
          <circle cx="40" cy="40" r="32" fill="none" stroke="#ffffff10" strokeWidth="6" />
          <circle cx="40" cy="40" r="32" fill="none" stroke={color} strokeWidth="6"
            strokeDasharray={`${(score / 100) * 201} 201`}
            strokeLinecap="round"
            transform="rotate(-90 40 40)"
            style={{ transition: "stroke-dasharray 1s ease", filter: `drop-shadow(0 0 6px ${color})` }}
          />
        </svg>
        <div style={{
          position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center",
          color, fontSize: "18px", fontWeight: 800, fontFamily: "'JetBrains Mono', monospace",
        }}>{score}</div>
      </div>
      <div>
        <div style={{ color: "#aaa", fontSize: "11px", letterSpacing: "0.1em" }}>RISK SCORE</div>
        <div style={{ color, fontSize: "20px", fontWeight: 700, fontFamily: "'Space Grotesk', sans-serif" }}>
          {score > 75 ? "CRITICAL" : score > 50 ? "HIGH" : score > 25 ? "MEDIUM" : "LOW"}
        </div>
      </div>
    </div>
  );
}

export default function OSINTDemo() {
  const [target, setTarget] = useState("");
  const [targetType, setTargetType] = useState("auto");
  const [phase, setPhase] = useState("idle"); // idle | scanning | results
  const [completedSteps, setCompletedSteps] = useState([]);
  const [currentStep, setCurrentStep] = useState(null);
  const [result, setResult] = useState(null);
  const [activeTab, setActiveTab] = useState("summary");
  const logRef = useRef(null);

  const demoTargets = Object.keys(DEMO_TARGETS);

const runScan = async (t) => {
    const tgt = t || target.trim();
    if (!tgt) return;
    setPhase("scanning");
    setCompletedSteps([]);
    setCurrentStep(null);
    setResult(null);
    setActiveTab("summary");

    for (let i = 0; i < STEPS.length; i++) {
      const step = STEPS[i];
      setCurrentStep(step.id);
      await new Promise(r => setTimeout(r, step.duration));
      setCompletedSteps(prev => [...prev, step.id]);
    }

    try {
      const response = await fetch(`/api/analyze?target=${encodeURIComponent(tgt)}`);
      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error("API error:", err);
    }

    setCurrentStep(null);
    setPhase("results");
  };

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [completedSteps, currentStep]);

  const reset = () => {
    setPhase("idle");
    setTarget("");
    setCompletedSteps([]);
    setCurrentStep(null);
    setResult(null);
  };
const exportJSON = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${target}-osint-report.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportPDF = () => {
    const doc = new jsPDF();
    const margin = 15;
    const pageWidth = doc.internal.pageSize.getWidth() - margin * 2;
    let y = 20;

    const addLine = (text, fontSize = 11, bold = false) => {
      doc.setFontSize(fontSize);
      doc.setFont("helvetica", bold ? "bold" : "normal");
      const lines = doc.splitTextToSize(text, pageWidth);
      lines.forEach(line => {
        if (y > 270) { doc.addPage(); y = 20; }
        doc.text(line, margin, y);
        y += fontSize * 0.5;
      });
      y += 4;
    };

    addLine(`OSINT Report: ${target}`, 16, true);
    addLine(`Generated: ${new Date().toUTCString()}`, 9);
    addLine(`Risk Score: ${result.riskScore ?? "N/A"}`, 11, true);
    y += 4;

    addLine("WHOIS", 13, true);
    Object.entries(result.whois || {}).forEach(([k, v]) => {
      addLine(`${k}: ${Array.isArray(v) ? v.join(", ") : v}`);
    });

    y += 4;
    addLine("AI REPORT", 13, true);
    addLine(result.report || "No report generated.");

    y += 4;
    addLine("INDICATORS", 13, true);
    (result.virustotal?.indicators || []).forEach(ind => {
      addLine(`[${ind.risk?.toUpperCase()}] ${ind.type}: ${ind.value} (${ind.source})`);
    });

    doc.save(`${target}-osint-report.pdf`);
  };
  return (
    <div style={{
      minHeight: "100vh",
      background: "#0a0c0f",
      color: "#e0e0e0",
      fontFamily: "'Inter', sans-serif",
      padding: "0",
    }}>
      {/* Header */}
      <div style={{
        borderBottom: "1px solid #ffffff10",
        padding: "16px 32px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        background: "#0d1017",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <div style={{
            width: 32, height: 32, borderRadius: "6px",
            background: "linear-gradient(135deg, #00e5ff, #0070f3)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: "16px", boxShadow: "0 0 16px #00e5ff44",
          }}>⬡</div>
          <div>
            <div style={{ fontWeight: 700, fontSize: "15px", letterSpacing: "0.02em", color: "#fff" }}>
              SENTINEL<span style={{ color: "#00e5ff" }}>OSINT</span>
            </div>
            <div style={{ fontSize: "11px", color: "#555", fontFamily: "'JetBrains Mono', monospace" }}>
              v0.4.1 · demo mode
            </div>
          </div>
        </div>
        
      </div>

      <div style={{ maxWidth: 960, margin: "0 auto", padding: "40px 24px" }}>

        {/* Input Section */}
        <div style={{ marginBottom: "32px" }}>
          <div style={{ fontSize: "24px", fontWeight: 700, color: "#fff", marginBottom: "4px" }}>
            Threat Intelligence Lookup
          </div>
          <div style={{ color: "#555", fontSize: "13px", marginBottom: "24px" }}>
            Aggregate OSINT from WHOIS, passive DNS, GitHub, AbuseIPDB, and threat intelligence feeds
          </div>

          <div style={{ display: "flex", gap: "8px", marginBottom: "16px" }}>
            <div style={{
              flex: 1, display: "flex", alignItems: "center",
              background: "#111418", border: "1px solid #ffffff15",
              borderRadius: "8px", padding: "0 16px",
              transition: "border-color 0.2s",
            }}>
              <span style={{ color: "#333", marginRight: "10px", fontSize: "14px" }}>$</span>
              <input
                value={target}
                onChange={e => setTarget(e.target.value)}
                onKeyDown={e => e.key === "Enter" && runScan()}
                placeholder="domain.com, IP address, username..."
                style={{
                  flex: 1, background: "none", border: "none", outline: "none",
                  color: "#e0e0e0", fontSize: "14px", fontFamily: "'JetBrains Mono', monospace",
                  padding: "14px 0",
                }}
              />
            </div>
            <select
              value={targetType}
              onChange={e => setTargetType(e.target.value)}
              style={{
                background: "#111418", border: "1px solid #ffffff15", color: "#888",
                borderRadius: "8px", padding: "0 12px", fontSize: "13px",
                fontFamily: "'JetBrains Mono', monospace", cursor: "pointer",
              }}
            >
              <option value="auto">auto-detect</option>
              <option value="domain">domain</option>
              <option value="ip">ip</option>
              <option value="username">username</option>
            </select>
            <button
              onClick={() => runScan()}
              disabled={phase === "scanning" || !target.trim()}
              style={{
                background: phase === "scanning" ? "#0a3a50" : "linear-gradient(135deg, #0070f3, #00e5ff)",
                border: "none", borderRadius: "8px", padding: "0 24px",
                color: "#fff", fontSize: "14px", fontWeight: 600, cursor: phase === "scanning" ? "not-allowed" : "pointer",
                opacity: !target.trim() ? 0.4 : 1,
                boxShadow: phase !== "scanning" && target.trim() ? "0 0 20px #0070f344" : "none",
                transition: "all 0.2s",
              }}
            >
              {phase === "scanning" ? "Scanning..." : "Analyze →"}
            </button>
          </div>

          {/* Demo targets */}
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ color: "#444", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
              demo:
            </span>
            {demoTargets.map(t => (
              <button key={t} onClick={() => { setTarget(t); runScan(t); }} style={{
                background: "#111418", border: "1px solid #ffffff10", borderRadius: "4px",
                padding: "4px 10px", color: "#00e5ff", fontSize: "12px",
                fontFamily: "'JetBrains Mono', monospace", cursor: "pointer",
                transition: "border-color 0.2s",
              }}>
                {t}
              </button>
            ))}
          </div>
        </div>

        {/* Scanning Phase */}
        {phase === "scanning" && (
          <div style={{
            background: "#0d1017", border: "1px solid #ffffff10", borderRadius: "12px",
            padding: "24px", marginBottom: "24px",
          }}>
            <div style={{ fontSize: "13px", color: "#555", marginBottom: "16px", fontFamily: "'JetBrains Mono', monospace" }}>
              // running analysis pipeline
            </div>
            <div ref={logRef} style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {STEPS.map(step => {
                const done = completedSteps.includes(step.id);
                const active = currentStep === step.id;
                return (
                  <div key={step.id} style={{
                    display: "flex", alignItems: "center", gap: "12px",
                    opacity: done ? 1 : active ? 1 : 0.3,
                    transition: "opacity 0.3s",
                  }}>
                    <div style={{ width: 20, textAlign: "center", fontSize: "14px" }}>
                      {done ? "✓" : active ? "⟳" : "○"}
                    </div>
                    <div style={{
                      fontFamily: "'JetBrains Mono', monospace", fontSize: "13px",
                      color: done ? "#00e676" : active ? "#00e5ff" : "#555",
                    }}>
                      {step.icon} {step.label}
                      {active && <span style={{ animation: "blink 1s infinite" }}>_</span>}
                    </div>
                    {done && (
                      <div style={{ marginLeft: "auto", color: "#00e67688", fontSize: "11px", fontFamily: "'JetBrains Mono', monospace" }}>
                        done
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Results */}
        {phase === "results" && result && (
          <div>
            {/* Top bar */}
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              marginBottom: "20px",
            }}>
              <div>
                <div style={{ color: "#555", fontSize: "11px", fontFamily: "'JetBrains Mono', monospace", marginBottom: "4px" }}>
                  ANALYSIS COMPLETE · {new Date().toUTCString()}
                </div>
                <div style={{ color: "#fff", fontSize: "20px", fontWeight: 700, fontFamily: "'JetBrains Mono', monospace" }}>
                  {target || demoTargets[0]}
                </div>
              </div>
              <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
                <ScoreMeter score={result.riskScore} />
                <button onClick={reset} style={{
                  background: "#111418", border: "1px solid #ffffff15", borderRadius: "6px",
                  padding: "8px 16px", color: "#888", fontSize: "13px", cursor: "pointer",
                }}>
                  ← New Scan
                </button>
              </div>
            </div>

            {/* Tabs */}
            <div style={{ display: "flex", gap: "4px", borderBottom: "1px solid #ffffff10", marginBottom: "20px" }}>
              {["summary", "indicators", "sources", "report"].map(tab => (
                <button key={tab} onClick={() => setActiveTab(tab)} style={{
                  background: "none", border: "none",
                  borderBottom: activeTab === tab ? "2px solid #00e5ff" : "2px solid transparent",
                  padding: "10px 16px", color: activeTab === tab ? "#00e5ff" : "#555",
                  fontSize: "13px", fontWeight: activeTab === tab ? 600 : 400,
                  cursor: "pointer", textTransform: "uppercase", letterSpacing: "0.05em",
                  fontFamily: "'JetBrains Mono', monospace",
                }}>
                  {tab}
                </button>
              ))}
              <div style={{ marginLeft: "auto", display: "flex", gap: "8px", padding: "6px 0" }}>
                <button onClick={exportJSON} style={{
                  background: "#111418", border: "1px solid #ffffff15", borderRadius: "5px",
                  padding: "5px 14px", color: "#888", fontSize: "12px", cursor: "pointer",
                }}>⬇ Export JSON</button>
                <button onClick={exportPDF} style={{
                  background: "#111418", border: "1px solid #ffffff15", borderRadius: "5px",
                  padding: "5px 14px", color: "#888", fontSize: "12px", cursor: "pointer",
                }}>⬇ Export PDF</button>
              </div>
            </div>

            {/* Summary Tab */}
            {activeTab === "summary" && (
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                <div style={{ background: "#0d1017", border: "1px solid #ffffff10", borderRadius: "10px", padding: "20px" }}>
                  <div style={{ color: "#555", fontSize: "11px", letterSpacing: "0.1em", marginBottom: "14px" }}>WHOIS DATA</div>
                  {Object.entries(result.whois).map(([k, v]) => (
                    <div key={k} style={{ display: "flex", justifyContent: "space-between", marginBottom: "10px", gap: "12px" }}>
                      <span style={{ color: "#555", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace", minWidth: 100 }}>{k}</span>
                      <span style={{ color: "#e0e0e0", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace", textAlign: "right", wordBreak: "break-all" }}>
                        {Array.isArray(v) ? v.join(", ") : v}
                      </span>
                    </div>
                  ))}
                </div>

                <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                  <div style={{ background: "#0d1017", border: "1px solid #ffffff10", borderRadius: "10px", padding: "20px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "14px" }}>
                      <div style={{ color: "#555", fontSize: "11px", letterSpacing: "0.1em" }}>GITHUB INTEL</div>
                      {(result.github?.raw?.total_count > 0) && (
                        <div style={{ color: "#555", fontSize: "11px", fontFamily: "'JetBrains Mono', monospace" }}>
                          {result.github.raw.relevant_count} relevant / {result.github.raw.total_count} total
                        </div>
                      )}
                    </div>
                    {(result.github?.raw?.repos || []).filter(r => r.relevant).length === 0 ? (
                      <div style={{ color: "#333", fontSize: "13px" }}>No relevant repositories found</div>
                    ) : (result.github.raw.repos.filter(r => r.relevant)).map((r, i) => (
                      <div key={i} style={{ borderLeft: "2px solid #ffffff15", paddingLeft: "12px", marginBottom: "12px" }}>
                        <a href={r.url} target="_blank" rel="noreferrer" style={{ color: "#00e5ff", fontSize: "11px", marginBottom: "4px", fontFamily: "'JetBrains Mono', monospace", textDecoration: "none", display: "block" }}>
                          {r.name}
                        </a>
                        {r.description && (
                          <div style={{ color: "#aaa", fontSize: "12px", marginBottom: "4px" }}>{r.description}</div>
                        )}
                        <div style={{ color: "#555", fontSize: "11px" }}>★ {r.stars}</div>
                      </div>
                    ))}
                  </div>
                  <div style={{ background: "#0d1017", border: "1px solid #ffffff10", borderRadius: "10px", padding: "20px" }}>
                    <div style={{ color: "#555", fontSize: "11px", letterSpacing: "0.1em", marginBottom: "14px" }}>THREAT FEEDS</div>
                    {[
                      { label: "OTX Pulses", value: result.otx?.raw?.pulse_count ?? "—", warn: (result.otx?.raw?.pulse_count || 0) > 0 },
                      { label: "AbuseIPDB Score", value: result.abuseipdb?.status === "not_applicable" ? "N/A" : `${result.abuseipdb?.raw?.abuseConfidenceScore ?? "—"}/100`, warn: (result.abuseipdb?.raw?.abuseConfidenceScore || 0) > 25 },
                      { label: "URLhaus", value: result.urlhaus?.status === "not_applicable" ? "N/A" : result.urlhaus?.verdict === "malicious" ? "Flagged" : result.urlhaus?.status === "not_found" ? "Clean" : "—", warn: result.urlhaus?.verdict === "malicious" },
                    ].map(({ label, value, warn }) => (
                      <div key={label} style={{ display: "flex", justifyContent: "space-between", marginBottom: "10px" }}>
                        <span style={{ color: "#555", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }}>{label}</span>
                        <span style={{ color: warn ? "#ff8c42" : "#00e676", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
                          {value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Indicators Tab */}
            {activeTab === "indicators" && (
              <div style={{ background: "#0d1017", border: "1px solid #ffffff10", borderRadius: "10px", overflow: "hidden" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid #ffffff10" }}>
                      {["Type", "Indicator", "Source", "Risk"].map(h => (
                        <th key={h} style={{ padding: "12px 16px", textAlign: "left", color: "#555", fontSize: "11px", letterSpacing: "0.1em", fontWeight: 500 }}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(result.virustotal?.indicators || []).map((ind, i) => (
                      <tr key={i} style={{ borderBottom: "1px solid #ffffff08" }}>
                        <td style={{ padding: "12px 16px", color: "#888", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }}>{ind.type}</td>
                        <td style={{ padding: "12px 16px", color: "#e0e0e0", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }}>{ind.value}</td>
                        <td style={{ padding: "12px 16px", color: "#555", fontSize: "12px" }}>{ind.source}</td>
                        <td style={{ padding: "12px 16px" }}><RiskBadge level={ind.risk} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Sources Tab */}
            {activeTab === "sources" && (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "12px" }}>
                {[
                  { name: "WHOIS", status: "success", records: 7, icon: "🔍" },
                  { name: "Passive DNS", status: "success", records: 3, icon: "🌐" },
                  { name: "GitHub", status: (result.github?.raw?.relevant_count || 0) > 0 ? "success" : "empty", records: result.github?.raw?.relevant_count || 0, icon: "💻" },
                  { name: "OTX", status: (result.otx?.raw?.pulse_count || 0) > 0 ? "success" : "empty", records: result.otx?.raw?.pulse_count || 0, icon: "🎯" },
                  { name: "AbuseIPDB", status: "success", records: 2, icon: "🛡️" },
                  { name: "VirusTotal", status: "partial", records: 1, icon: "🔬" },
                ].map(s => (
                  <div key={s.name} style={{
                    background: "#0d1017", border: "1px solid #ffffff10", borderRadius: "10px", padding: "16px",
                  }}>
                    <div style={{ fontSize: "20px", marginBottom: "8px" }}>{s.icon}</div>
                    <div style={{ color: "#fff", fontWeight: 600, fontSize: "14px", marginBottom: "4px" }}>{s.name}</div>
                    <div style={{ color: s.status === "success" ? "#00e676" : s.status === "empty" ? "#555" : "#ffd700", fontSize: "12px" }}>
                      {s.status === "success" ? `${s.records} records` : s.status === "empty" ? "No data" : "Partial"}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Report Tab */}
            {activeTab === "report" && (
              <div style={{ background: "#0d1017", border: "1px solid #ffffff10", borderRadius: "10px", padding: "28px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "20px" }}>
                  <div style={{ fontSize: "14px" }}>🤖</div>
                  <div style={{ color: "#555", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
                    AI-generated analysis · claude-sonnet-4 · {new Date().toLocaleDateString()}
                  </div>
                </div>
                <div style={{
                  color: "#ccc", fontSize: "14px", lineHeight: "1.8",
                  whiteSpace: "pre-wrap", fontFamily: "Georgia, serif",
                  borderLeft: "2px solid #00e5ff44", paddingLeft: "20px",
                }}>
                  {typeof result.report === 'object' ? (
  <div>
    <div style={{ marginBottom: "16px" }}>
      <span style={{ color: result.report.verdict === "malicious" ? "#ff4444" : result.report.verdict === "suspicious" ? "#ffaa00" : "#00e5ff", fontWeight: "bold", textTransform: "uppercase", fontSize: "13px" }}>
        {result.report.verdict}
      </span>
      <span style={{ color: "#555", fontSize: "12px", marginLeft: "10px" }}>confidence: {result.report.confidence}</span>
    </div>
    <p style={{ marginBottom: "20px" }}>{result.report.summary}</p>
    {result.report.key_findings?.length > 0 && (
      <div style={{ marginBottom: "20px" }}>
        <div style={{ color: "#00e5ff", fontSize: "12px", marginBottom: "10px" }}>KEY FINDINGS</div>
        {result.report.key_findings.map((f, i) => (
          <div key={i} style={{ marginBottom: "8px", paddingLeft: "12px", borderLeft: "2px solid #00e5ff44" }}>• {f}</div>
        ))}
      </div>
    )}
    {result.report.recommended_actions?.length > 0 && (
      <div>
        <div style={{ color: "#00e5ff", fontSize: "12px", marginBottom: "10px" }}>RECOMMENDED ACTIONS</div>
        {result.report.recommended_actions.map((a, i) => (
          <div key={i} style={{ marginBottom: "8px", paddingLeft: "12px", borderLeft: "2px solid #ffffff22" }}>• {a}</div>
        ))}
      </div>
    )}
  </div>
) : result.report}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Idle state hint */}
        {phase === "idle" && (
          <div style={{
            border: "1px dashed #ffffff10", borderRadius: "12px", padding: "60px",
            textAlign: "center", color: "#333",
          }}>
            <div style={{ fontSize: "32px", marginBottom: "12px" }}>⬡</div>
            <div style={{ fontSize: "14px", fontFamily: "'JetBrains Mono', monospace" }}>
              Enter a target or click a demo above to run an analysis
            </div>
          </div>
        )}
      </div>

      <style>{`
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0; } }
        * { box-sizing: border-box; }
        input::placeholder { color: #333; }
        select option { background: #0d1017; }
        button:hover { opacity: 0.85; }
      `}</style>
    </div>
  );
}
