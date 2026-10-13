"use client";

import { useState, useEffect } from "react";
import { 
  ShieldAlert, ShieldCheck, Terminal, Code, Wrench, 
  CheckCircle2, Sparkles, Download, FileJson, GitCompare, Edit3,
  History, X, Clock, AlertTriangle, Shield, Copy, Check, Filter,
  Layers, Cpu, Zap
} from "lucide-react";
import { diffLines, Change } from "diff";

interface Finding {
  id: string;
  rule_id: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  file_path: string;
  line_number: number;
  description: string;
  ai_root_cause: string;
  ai_suggested_patch: string;
}

interface ScanResult {
  id: string;
  project_id: string;
  status: string;
  total_findings: number;
  findings: Finding[];
}

interface HistoryItem {
  id: string;
  project_name: string;
  status: string;
  total_findings: number;
  created_at: string;
  findings: Finding[];
}

const DEFAULT_IAC = `resource "aws_s3_bucket" "prod_storage" {
  bucket = "company-sensitive-data-bucket"
}

resource "aws_security_group" "allow_ssh" {
  name        = "allow-public-ssh"
  description = "Security group for public SSH access"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}`;

export default function Home() {
  const [originalIac, setOriginalIac] = useState(DEFAULT_IAC);
  const [iacCode, setIacCode] = useState(DEFAULT_IAC);
  const [loading, setLoading] = useState(false);
  const [remediatingAll, setRemediatingAll] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [appliedRule, setAppliedRule] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"editor" | "diff">("editor");
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [copiedCode, setCopiedCode] = useState(false);

  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyList, setHistoryList] = useState<HistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await fetch("https://cloudsec-ai.onrender.com/api/v1/scans/history");
      if (res.ok) {
        const data = await res.json();
        setHistoryList(data);
      }
    } catch (err) {
      console.error("Failed to load history:", err);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    if (historyOpen) fetchHistory();
  }, [historyOpen]);

  const runScan = async (codeToScan: string) => {
    setLoading(true);
    try {
      const res = await fetch("https://cloudsec-ai.onrender.com/api/v1/scans/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_name: "Production-Audit",
          raw_iac_code: codeToScan,
        }),
      });
      const data = await res.json();
      setScanResult(data);
      fetchHistory();
    } catch (err) {
      console.error(err);
      alert("Scanner API unavailable. Ensure cloudsec-api container is active.");
    } finally {
      setLoading(false);
    }
  };

  const applySinglePatch = (currentCode: string, finding: Finding): string => {
    let updatedCode = currentCode;
    const patch = finding.ai_suggested_patch;

    if (finding.rule_id === "CKV_AWS_24") {
      const insecureIngressPattern = /ingress\s*\{[^}]*from_port\s*=\s*22[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\][^}]*\}/;
      if (insecureIngressPattern.test(updatedCode)) {
        updatedCode = updatedCode.replace(insecureIngressPattern, patch.trim());
      } else {
        updatedCode = `${updatedCode}\n\n${patch}`;
      }
    } else if (finding.rule_id === "CKV_AWS_23") {
      const sgPattern = /(resource\s+"aws_security_group"\s+"[a-zA-Z0-9_-]+"\s*\{[\s\S]*?name\s*=\\s*"[^"]+")/;
      if (sgPattern.test(updatedCode)) {
        updatedCode = updatedCode.replace(sgPattern, `$1\n${patch.trim()}`);
      } else {
        updatedCode = `${updatedCode}\n\n${patch}`;
      }
    } else {
      updatedCode = `${updatedCode.trim()}\n\n${patch}\n`;
    }

    return updatedCode;
  };

  const handleApplyPatch = async (finding: Finding) => {
    const updated = applySinglePatch(iacCode, finding);
    setIacCode(updated);
    setAppliedRule(finding.rule_id);
    setTimeout(() => setAppliedRule(null), 2500);
    await runScan(updated);
  };

  const handleAutoRemediateAll = async () => {
    if (!scanResult || scanResult.findings.length === 0) return;
    setRemediatingAll(true);

    let hardenedCode = iacCode;
    for (const finding of scanResult.findings) {
      if (finding.ai_suggested_patch && !finding.ai_suggested_patch.startsWith("# Remediation: Apply least-privilege")) {
        hardenedCode = applySinglePatch(hardenedCode, finding);
      }
    }

    setIacCode(hardenedCode);
    setViewMode("diff");
    await runScan(hardenedCode);
    setRemediatingAll(false);
  };

  const handleCopyCode = () => {
    navigator.clipboard.writeText(iacCode);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const handleDownloadHcl = () => {
    const blob = new Blob([iacCode], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "hardened-main.tf";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleExportJsonReport = () => {
    if (!scanResult) return;
    const reportPayload = {
      audit_meta: {
        engine: "CloudSecAI Core Guard v1.0",
        timestamp: new Date().toISOString(),
        status: scanResult.status,
        total_violations: scanResult.total_findings,
        compliance_state: scanResult.total_findings === 0 ? "PASSED" : "FAILED",
      },
      audit_findings: scanResult.findings,
      remediated_hcl_snapshot: iacCode,
    };

    const blob = new Blob([JSON.stringify(reportPayload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `cloudsec-audit-${Date.now()}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const loadPastRun = (item: HistoryItem) => {
    setScanResult({
      id: item.id,
      project_id: item.project_name,
      status: item.status,
      total_findings: item.total_findings,
      findings: item.findings,
    });
    setHistoryOpen(false);
  };

  const diffResult: Change[] = diffLines(originalIac, iacCode);

  const filteredFindings = scanResult?.findings.filter((f) => {
    if (filterSeverity === "ALL") return true;
    return f.severity === filterSeverity;
  }) || [];

  const criticalCount = scanResult?.findings.filter((f) => f.severity === "CRITICAL").length || 0;
  const highCount = scanResult?.findings.filter((f) => f.severity === "HIGH").length || 0;
  const mediumCount = scanResult?.findings.filter((f) => f.severity === "MEDIUM").length || 0;
  const codeLines = iacCode.split("\n");

  return (
    <main className="min-h-screen bg-[#080B11] text-zinc-200 flex flex-col font-mono selection:bg-cyan-500/20 selection:text-cyan-300">
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute -top-40 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl"></div>
        <div className="absolute top-1/3 -right-40 w-96 h-96 bg-blue-600/5 rounded-full blur-3xl"></div>
      </div>

      <header className="relative z-10 border-b border-zinc-800/80 bg-[#0B0F17]/80 backdrop-blur-xl px-6 py-3.5">
        <div className="max-w-[1400px] mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <div className="p-2.5 rounded-xl bg-gradient-to-b from-cyan-500/20 to-blue-600/10 border border-cyan-500/30 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
              <span className="absolute -bottom-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full ring-2 ring-[#0B0F17]"></span>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-bold tracking-tight text-white font-sans">
                  CloudSec<span className="text-cyan-400">AI</span>
                </span>
                <span className="text-[10px] uppercase tracking-wider font-semibold px-2 py-0.5 rounded-md bg-zinc-800/80 text-zinc-400 border border-zinc-700/60 font-mono">
                  v1.0-STABLE
                </span>
              </div>
              <p className="text-[11px] text-zinc-500 font-sans tracking-wide">Autonomous IaC Posture & Remediation Engine</p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 font-sans">
            <button
              onClick={() => setHistoryOpen(true)}
              className="bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 hover:border-zinc-700 text-xs px-3.5 py-1.5 rounded-lg flex items-center gap-2 transition-all cursor-pointer shadow-sm"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              Audit Runs
            </button>
            <button
              onClick={handleDownloadHcl}
              className="bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 hover:border-zinc-700 text-xs px-3.5 py-1.5 rounded-lg flex items-center gap-2 transition-all cursor-pointer shadow-sm"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              Export .tf
            </button>
            {scanResult && (
              <button
                onClick={handleExportJsonReport}
                className="bg-zinc-900/90 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 hover:border-zinc-700 text-xs px-3.5 py-1.5 rounded-lg flex items-center gap-2 transition-all cursor-pointer shadow-sm"
              >
                <FileJson className="w-3.5 h-3.5 text-emerald-400" />
                Report JSON
              </button>
            )}
            <div className="h-4 w-px bg-zinc-800 mx-1"></div>
            <div className="flex items-center gap-2 bg-emerald-950/30 border border-emerald-500/20 px-3 py-1 rounded-lg text-[11px] text-emerald-400 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              CORE ONLINE
            </div>
          </div>
        </div>
      </header>

      <div className="relative z-10 max-w-[1400px] mx-auto w-full p-6 space-y-6 flex-1">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-sans">
          <div className="bg-[#0D121D]/90 border border-zinc-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden group hover:border-zinc-700/80 transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider text-zinc-400 font-medium">Total Misconfigurations</span>
              <Layers className="w-4 h-4 text-zinc-500" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white font-mono">{scanResult ? scanResult.total_findings : 0}</span>
              <span className="text-xs text-zinc-500">active alerts</span>
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-500/50 to-transparent"></div>
          </div>

          <div className="bg-[#0D121D]/90 border border-zinc-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden group hover:border-zinc-700/80 transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider text-rose-400 font-medium">Critical / High</span>
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-rose-400 font-mono">{criticalCount + highCount}</span>
              <span className="text-xs text-rose-500/70">blocking merge</span>
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-rose-500/50 to-transparent"></div>
          </div>

          <div className="bg-[#0D121D]/90 border border-zinc-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden group hover:border-zinc-700/80 transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider text-amber-400 font-medium">Medium / Low</span>
              <Wrench className="w-4 h-4 text-amber-400" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-amber-400 font-mono">{mediumCount}</span>
              <span className="text-xs text-amber-500/70">warnings</span>
            </div>
            <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-amber-500/50 to-transparent"></div>
          </div>

          <div className="bg-[#0D121D]/90 border border-zinc-800/80 rounded-xl p-4 shadow-sm relative overflow-hidden group hover:border-zinc-700/80 transition-all">
            <div className="flex items-center justify-between">
              <span className="text-[11px] uppercase tracking-wider text-zinc-400 font-medium">CIS Compliance Gate</span>
              <Cpu className="w-4 h-4 text-zinc-500" />
            </div>
            <div className="mt-2 flex items-center gap-2">
              {scanResult ? (
                scanResult.total_findings === 0 ? (
                  <span className="text-sm font-bold text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4" /> PASSED (READY)
                  </span>
                ) : (
                  <span className="text-sm font-bold text-rose-400 flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4" /> REMEDIATION REQUIRED
                  </span>
                )
              ) : (
                <span className="text-sm font-semibold text-zinc-400">AWAITING SCAN</span>
              )}
            </div>
            <div className={`absolute bottom-0 left-0 right-0 h-0.5 ${
              scanResult && scanResult.total_findings === 0
                ? "bg-gradient-to-r from-emerald-500/50 to-transparent"
                : "bg-gradient-to-r from-cyan-500/50 to-transparent"
            }`}></div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
          <div className="bg-[#0B0F17] border border-zinc-800/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
            <div className="px-4 py-3 bg-[#0F1420] border-b border-zinc-800/80 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-2 text-xs font-semibold text-zinc-200">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  main.tf
                </span>
                <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-xs font-sans">
                  <button
                    onClick={() => setViewMode("editor")}
                    className={`px-2.5 py-1 rounded flex items-center gap-1.5 cursor-pointer transition-colors ${
                      viewMode === "editor" ? "bg-zinc-800 text-cyan-300 font-medium" : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    <Edit3 className="w-3.5 h-3.5" /> Editor
                  </button>
                  <button
                    onClick={() => setViewMode("diff")}
                    className={`px-2.5 py-1 rounded flex items-center gap-1.5 cursor-pointer transition-colors ${
                      viewMode === "diff" ? "bg-zinc-800 text-emerald-300 font-medium" : "text-zinc-400 hover:text-zinc-200"
                    }`}
                  >
                    <GitCompare className="w-3.5 h-3.5" /> Diff Inspector
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyCode}
                  className="p-1.5 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800 rounded-lg transition-colors cursor-pointer"
                  title="Copy Code"
                >
                  {copiedCode ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => {
                    setOriginalIac(iacCode);
                    runScan(iacCode);
                  }}
                  disabled={loading || remediatingAll}
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4 py-1.5 rounded-lg text-xs font-sans flex items-center gap-2 transition-all cursor-pointer shadow-[0_0_20px_rgba(6,182,212,0.25)] hover:shadow-[0_0_25px_rgba(6,182,212,0.4)] disabled:opacity-50"
                >
                  {loading ? (
                    <>
                      <div className="w-3 h-3 border-2 border-slate-950 border-t-transparent rounded-full animate-spin"></div>
                      Auditing IaC...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3.5 h-3.5 text-slate-950" /> Trigger AI Audit
                    </>
                  )}
                </button>
              </div>
            </div>

            {viewMode === "editor" ? (
              <div className="relative flex h-[580px] bg-[#080B11] text-xs font-mono overflow-hidden">
                <div className="w-12 py-4 select-none bg-[#090D14] border-r border-zinc-800/80 text-zinc-600 text-right pr-3 font-mono leading-relaxed space-y-0.5">
                  {codeLines.map((_, i) => (
                    <div key={i}>{i + 1}</div>
                  ))}
                </div>
                <textarea
                  value={iacCode}
                  onChange={(e) => setIacCode(e.target.value)}
                  className="flex-1 bg-transparent p-4 text-zinc-200 focus:outline-none resize-none leading-relaxed selection:bg-cyan-500/20"
                  spellCheck="false"
                />
              </div>
            ) : (
              <div className="h-[580px] p-4 bg-[#080B11] overflow-y-auto font-mono text-xs leading-relaxed space-y-1">
                <div className="text-[11px] text-zinc-500 border-b border-zinc-800 pb-2 mb-3 flex justify-between font-sans">
                  <span>Original Insecure Baseline</span>
                  <span className="text-emerald-400">Remediated Compliant Code</span>
                </div>
                {diffResult.map((part, index) => {
                  const color = part.added
                    ? "bg-emerald-950/40 text-emerald-300 border-l-2 border-emerald-500 pl-3 py-0.5 rounded-r"
                    : part.removed
                    ? "bg-rose-950/40 text-rose-300 border-l-2 border-rose-500 pl-3 py-0.5 line-through opacity-75 rounded-r"
                    : "text-zinc-400 pl-3 py-0.5";
                  const prefix = part.added ? "+ " : part.removed ? "- " : "  ";
                  return (
                    <div key={index} className={color}>
                      {part.value.split("\n").map((line, lIdx) =>
                        line ? <div key={lIdx}>{prefix}{line}</div> : null
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          <div className="bg-[#0B0F17] border border-zinc-800/80 rounded-2xl shadow-2xl flex flex-col overflow-hidden">
            <div className="px-4 py-3 bg-[#0F1420] border-b border-zinc-800/80 flex items-center justify-between font-sans">
              <span className="flex items-center gap-2 text-xs font-semibold text-zinc-200">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Security Findings & Patches
              </span>

              <div className="flex items-center gap-2">
                {scanResult && scanResult.total_findings > 0 && (
                  <button
                    onClick={handleAutoRemediateAll}
                    disabled={loading || remediatingAll}
                    className="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-[11px] font-semibold px-2.5 py-1 rounded-md flex items-center gap-1.5 transition-all cursor-pointer shadow-sm disabled:opacity-50"
                  >
                    {remediatingAll ? (
                      <>
                        <div className="w-3 h-3 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin"></div>
                        Auto-Remediating...
                      </>
                    ) : (
                      <>
                        <Zap className="w-3.5 h-3.5 text-emerald-400 fill-emerald-400" /> Auto-Remediate All
                      </>
                    )}
                  </button>
                )}

                {scanResult && scanResult.total_findings > 0 && (
                  <div className="flex items-center gap-1 bg-zinc-900 border border-zinc-800 rounded-lg p-0.5 text-[11px]">
                    {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
                      <button
                        key={sev}
                        onClick={() => setFilterSeverity(sev)}
                        className={`px-2 py-0.5 rounded cursor-pointer transition-colors ${
                          filterSeverity === sev ? "bg-zinc-800 text-cyan-300 font-bold" : "text-zinc-400 hover:text-zinc-200"
                        }`}
                      >
                        {sev}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>

            <div className="h-[580px] overflow-y-auto p-4 space-y-4">
              {!scanResult ? (
                <div className="h-full border border-dashed border-zinc-800/80 rounded-xl flex flex-col items-center justify-center text-center p-8 space-y-3 font-sans">
                  <div className="p-3 bg-zinc-900 rounded-full border border-zinc-800 text-cyan-400">
                    <Code className="w-7 h-7" />
                  </div>
                  <h3 className="text-sm font-semibold text-zinc-300">Ready for Static Analysis</h3>
                  <p className="text-xs text-zinc-500 max-w-xs leading-relaxed">
                    Click "Trigger AI Audit" to execute Checkov security rules and load automated Terraform remediation patches.
                  </p>
                </div>
              ) : scanResult.total_findings === 0 ? (
                <div className="h-full border border-emerald-900/40 bg-emerald-950/10 rounded-xl flex flex-col items-center justify-center text-center p-8 space-y-3 font-sans">
                  <div className="p-3 bg-emerald-500/10 rounded-full border border-emerald-500/30">
                    <Sparkles className="w-8 h-8 text-emerald-400 animate-bounce" />
                  </div>
                  <h3 className="text-base font-bold text-emerald-300">Zero Security Misconfigurations Found</h3>
                  <p className="text-xs text-emerald-400/80 max-w-sm leading-relaxed">
                    All CIS benchmarks and AWS security controls have been satisfied. Infrastructure code is production-ready.
                  </p>
                </div>
              ) : (
                filteredFindings.map((finding) => (
                  <div
                    key={finding.id}
                    className="bg-[#0E131F] border border-zinc-800/80 hover:border-zinc-700 rounded-xl p-4 space-y-3 transition-all shadow-sm"
                  >
                    <div className="flex items-center justify-between font-mono">
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-cyan-400 font-semibold px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60">
                          {finding.rule_id}
                        </span>
                        <span className="text-[11px] text-zinc-500">line {finding.line_number}</span>
                      </div>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${
                        finding.severity === "CRITICAL" || finding.severity === "HIGH"
                          ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
                          : "bg-amber-500/10 text-amber-400 border-amber-500/30"
                      }`}>
                        {finding.severity}
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-zinc-200 font-sans leading-snug">{finding.title}</h4>

                    <div className="bg-[#090D14] p-3 rounded-lg border border-zinc-800/80 space-y-1 font-sans">
                      <span className="text-[10px] uppercase tracking-wider text-zinc-400 font-semibold block">AI Root Cause</span>
                      <p className="text-xs text-zinc-300 leading-relaxed">{finding.ai_root_cause}</p>
                    </div>

                    {finding.ai_suggested_patch && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between font-sans">
                          <span className="text-[11px] text-emerald-400 font-semibold flex items-center gap-1.5">
                            <Sparkles className="w-3.5 h-3.5" /> AI Automated Patch
                          </span>
                          <button
                            onClick={() => handleApplyPatch(finding)}
                            disabled={loading || remediatingAll}
                            className="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-semibold px-3 py-1 rounded-md flex items-center gap-1.5 transition-all cursor-pointer disabled:opacity-50"
                          >
                            {appliedRule === finding.rule_id ? (
                              <>
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> Patched!
                              </>
                            ) : (
                              <>
                                <Wrench className="w-3.5 h-3.5" /> Apply Patch
                              </>
                            )}
                          </button>
                        </div>
                        <pre className="bg-[#070A0F] border border-emerald-950/60 p-3 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap leading-relaxed">
                          {finding.ai_suggested_patch}
                        </pre>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>

      {historyOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/75 backdrop-blur-sm font-sans">
          <div className="w-full max-w-md bg-[#0B0F17] border-l border-zinc-800 h-full p-6 flex flex-col space-y-6 shadow-2xl">
            <div className="flex justify-between items-center border-b border-zinc-800 pb-4">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-cyan-400" />
                <h2 className="text-sm font-bold text-zinc-100 tracking-wide">Audit Run History</h2>
              </div>
              <button
                onClick={() => setHistoryOpen(false)}
                className="text-zinc-400 hover:text-zinc-200 p-1 rounded-md cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-3 pr-1">
              {loadingHistory ? (
                <p className="text-xs text-zinc-400 text-center py-8">Fetching audit history...</p>
              ) : historyList.length === 0 ? (
                <p className="text-xs text-zinc-500 text-center py-8">No historical audits recorded.</p>
              ) : (
                historyList.map((item) => (
                  <div
                    key={item.id}
                    onClick={() => loadPastRun(item)}
                    className="p-3.5 rounded-xl bg-[#0E131F] border border-zinc-800/80 hover:border-cyan-500/50 cursor-pointer transition-all space-y-2 group"
                  >
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-xs text-zinc-200 group-hover:text-cyan-400 transition-colors">
                        {item.project_name}
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded-full font-bold font-mono border ${
                        item.total_findings === 0
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                          : "bg-rose-500/10 text-rose-400 border-rose-500/30"
                      }`}>
                        {item.total_findings === 0 ? "PASSED" : `${item.total_findings} ISSUES`}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-[11px] text-zinc-500 font-mono">
                      <Clock className="w-3.5 h-3.5" />
                      <span>{item.created_at ? new Date(item.created_at).toLocaleString() : "Recent"}</span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
