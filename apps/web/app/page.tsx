"use client";

import { useState, useEffect } from "react";
import { 
  ShieldAlert, ShieldCheck, Terminal, Code, Wrench, 
  CheckCircle2, Sparkles, Download, FileJson, GitCompare, Edit3,
  History, X, Clock, AlertTriangle
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
  name = "allow-public-ssh"
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
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [appliedRule, setAppliedRule] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"editor" | "diff">("editor");

  const [historyOpen, setHistoryOpen] = useState(false);
  const [historyList, setHistoryList] = useState<HistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/scans/history");
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
    if (historyOpen) {
      fetchHistory();
    }
  }, [historyOpen]);

  const runScan = async (codeToScan: string) => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/scans/submit", {
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
      alert("Failed to connect to scanner API backend.");
    } finally {
      setLoading(false);
    }
  };

  const handleApplyPatch = async (finding: Finding) => {
    let updatedCode = iacCode;
    const patch = finding.ai_suggested_patch;

    if (finding.rule_id === "CKV_AWS_24") {
      const insecureIngressPattern = /ingress\s*\{[^}]*from_port\s*=\s*22[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\][^}]*\}/;
      if (insecureIngressPattern.test(updatedCode)) {
        updatedCode = updatedCode.replace(insecureIngressPattern, patch.trim());
      } else {
        updatedCode = `${updatedCode}\n\n${patch}`;
      }
    } else if (finding.rule_id === "CKV_AWS_23") {
      const sgPattern = /(resource\s+"aws_security_group"\s+"[a-zA-Z0-9_-]+"\s*\{[\s\S]*?name\s*=\s*"[^"]+")/;
      if (sgPattern.test(updatedCode)) {
        updatedCode = updatedCode.replace(sgPattern, `$1\n${patch.trim()}`);
      } else {
        updatedCode = `${updatedCode}\n\n${patch}`;
      }
    } else {
      updatedCode = `${updatedCode.trim()}\n\n${patch}\n`;
    }

    setIacCode(updatedCode);
    setAppliedRule(finding.rule_id);
    setTimeout(() => setAppliedRule(null), 2500);

    await runScan(updatedCode);
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
        engine: "CloudSecAI Core Scanner v1.0",
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

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-8 relative">
      <div className="max-w-7xl mx-auto space-y-8">
        <header className="flex justify-between items-center border-b border-slate-800 pb-6">
          <div className="flex items-center space-x-3">
            <ShieldAlert className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold tracking-tight">CloudSecAI</h1>
              <p className="text-sm text-slate-400">Autonomous IaC Security Scanner & AI Patch Engine</p>
            </div>
          </div>
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setHistoryOpen(true)}
              className="bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Audit Scan History"
            >
              <History className="w-3.5 h-3.5 text-cyan-400" />
              Scan History
            </button>
            <button
              onClick={handleDownloadHcl}
              className="bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
              title="Download Current Terraform HCL"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              Download .tf
            </button>
            {scanResult && (
              <button
                onClick={handleExportJsonReport}
                className="bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 text-xs px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-colors cursor-pointer"
                title="Export Comprehensive JSON Audit Report"
              >
                <FileJson className="w-3.5 h-3.5 text-emerald-400" />
                Export Audit JSON
              </button>
            )}
            <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 px-3.5 py-1.5 rounded-full text-xs text-emerald-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>API Engine Online</span>
            </div>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <section className="space-y-4">
            <div className="flex justify-between items-center">
              <div className="flex items-center gap-3">
                <span className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" /> Terraform Infrastructure Code
                </span>
                <div className="flex items-center bg-slate-900 border border-slate-800 rounded-lg p-0.5 text-xs">
                  <button
                    onClick={() => setViewMode("editor")}
                    className={`px-2.5 py-1 rounded flex items-center gap-1 cursor-pointer transition-colors ${
                      viewMode === "editor" ? "bg-slate-800 text-cyan-300 font-medium" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <Edit3 className="w-3 h-3" /> Editor
                  </button>
                  <button
                    onClick={() => setViewMode("diff")}
                    className={`px-2.5 py-1 rounded flex items-center gap-1 cursor-pointer transition-colors ${
                      viewMode === "diff" ? "bg-slate-800 text-emerald-300 font-medium" : "text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    <GitCompare className="w-3 h-3" /> Diff View
                  </button>
                </div>
              </div>
              <button
                onClick={() => {
                  setOriginalIac(iacCode);
                  runScan(iacCode);
                }}
                disabled={loading}
                className="bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-slate-950 font-semibold px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-500/10"
              >
                {loading ? "Analyzing Engine..." : "Trigger AI Audit"}
              </button>
            </div>

            {viewMode === "editor" ? (
              <textarea
                value={iacCode}
                onChange={(e) => setIacCode(e.target.value)}
                className="w-full h-[560px] bg-slate-900 border border-slate-800 rounded-xl p-4 font-mono text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 leading-relaxed"
                spellCheck="false"
              />
            ) : (
              <div className="w-full h-[560px] bg-slate-900 border border-slate-800 rounded-xl p-4 font-mono text-xs overflow-y-auto leading-relaxed">
                <div className="text-slate-500 border-b border-slate-800 pb-2 mb-2 flex justify-between">
                  <span>--- Original Insecure Baseline</span>
                  <span className="text-emerald-400">+++ Remediated Compliant Code</span>
                </div>
                {diffResult.map((part, index) => {
                  const color = part.added
                    ? "bg-emerald-950/40 text-emerald-300 border-l-2 border-emerald-500 pl-2 block"
                    : part.removed
                    ? "bg-rose-950/40 text-rose-300 border-l-2 border-rose-500 pl-2 block line-through opacity-75"
                    : "text-slate-400 pl-2.5 block";
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
          </section>

          <section className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> Audit Findings & Patches
              </span>
              {scanResult && (
                <span className={`text-xs px-3 py-1 rounded-full font-medium border transition-all ${
                  scanResult.total_findings === 0
                    ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/40"
                    : "bg-rose-500/20 text-rose-300 border-rose-500/30"
                }`}>
                  {scanResult.total_findings === 0 ? "All Resources Compliant" : `${scanResult.total_findings} Misconfigurations Detected`}
                </span>
              )}
            </div>

            <div className="h-[560px] overflow-y-auto space-y-4 pr-1">
              {!scanResult ? (
                <div className="h-full border border-dashed border-slate-800 rounded-xl flex flex-col items-center justify-center text-slate-500 space-y-3">
                  <Code className="w-10 h-10 stroke-[1.5]" />
                  <p className="text-sm">Submit Terraform code on the left to run security analysis.</p>
                </div>
              ) : scanResult.total_findings === 0 ? (
                <div className="h-full border border-emerald-900/40 bg-emerald-950/10 rounded-xl flex flex-col items-center justify-center text-emerald-300 space-y-3 p-8 text-center">
                  <Sparkles className="w-12 h-12 text-emerald-400 animate-bounce" />
                  <h3 className="text-lg font-semibold text-emerald-200">Zero Security Misconfigurations Found</h3>
                  <p className="text-xs text-emerald-400/80 max-w-sm">
                    All CIS benchmarks and AWS cloud compliance standards have been satisfied. Infrastructure is hardened and production-ready.
                  </p>
                </div>
              ) : (
                scanResult.findings.map((finding) => (
                  <div key={finding.id} className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs text-cyan-400 font-semibold">{finding.rule_id}</span>
                      <span className="text-xs px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20 font-medium">
                        {finding.severity}
                      </span>
                    </div>

                    <h3 className="font-medium text-sm text-slate-200">{finding.title}</h3>

                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800/80 space-y-1">
                      <p className="text-xs text-slate-400 font-semibold">AI Root Cause:</p>
                      <p className="text-xs text-slate-300 leading-relaxed">{finding.ai_root_cause}</p>
                    </div>

                    {finding.ai_suggested_patch && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <p className="text-xs text-emerald-400 font-semibold">AI Automated Remediation Patch:</p>
                          <button
                            onClick={() => handleApplyPatch(finding)}
                            disabled={loading}
                            className="bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs px-2.5 py-1 rounded flex items-center gap-1.5 transition-colors cursor-pointer disabled:opacity-50"
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
                        <pre className="bg-slate-950 border border-emerald-950/60 p-3 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto whitespace-pre-wrap">
                          {finding.ai_suggested_patch}
                        </pre>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </section>
        </div>
      </div>

      {/* Slide-over Audit History Drawer */}
      {historyOpen && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md bg-slate-900 border-l border-slate-800 h-full p-6 flex flex-col space-y-6 shadow-2xl">
            <div className="flex justify-between items-center border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-cyan-400" />
                <h2 className="text-lg font-bold text-slate-100">Audit Run History</h2>
              </div>
              <button
                onClick={() => setHistoryOpen(false)}
                className="text-slate-400 hover:text-slate-200 p-1 rounded-md"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-3 pr-1">
              {loadingHistory ? (
                <p className="text-sm text-slate-400 text-center py-8">Loading persisted audits...</p>
              ) : historyList.length === 0 ? (
                <p className="text-sm text-slate-500 text-center py-8">No audit history found.</p>
              ) : (
                historyList.map((item) => (
                  <div
                    key={item.id}
                    onClick={() => loadPastRun(item)}
                    className="p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition-all space-y-2 group"
                  >
                    <div className="flex justify-between items-center">
                      <span className="font-semibold text-sm text-slate-200 group-hover:text-cyan-400 transition-colors">
                        {item.project_name}
                      </span>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                        item.total_findings === 0
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                          : "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                      }`}>
                        {item.total_findings === 0 ? "Compliant" : `${item.total_findings} Findings`}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-xs text-slate-500">
                      <Clock className="w-3.5 h-3.5" />
                      <span>{item.created_at ? new Date(item.created_at).toLocaleString() : "Just now"}</span>
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
