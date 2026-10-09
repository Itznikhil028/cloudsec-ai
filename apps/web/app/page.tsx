"use client";

import { useState } from "react";
import { ShieldAlert, ShieldCheck, Terminal, Code, Wrench, CheckCircle2, Sparkles } from "lucide-react";

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
  const [iacCode, setIacCode] = useState(DEFAULT_IAC);
  const [loading, setLoading] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [appliedRule, setAppliedRule] = useState<string | null>(null);

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
      const insecureIngressPattern = /ingress\s*\{[^}]*from_port\s*=\s*22[^}]*cidr_blocks\s*=\s*\["0\.0\.0\.0\/0"\][^}]*\}/s;
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

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-7xl mx-auto space-y-8">
        <header className="flex justify-between items-center border-b border-slate-800 pb-6">
          <div className="flex items-center space-x-3">
            <ShieldAlert className="w-8 h-8 text-cyan-400" />
            <div>
              <h1 className="text-2xl font-bold tracking-tight">CloudSecAI</h1>
              <p className="text-sm text-slate-400">Autonomous IaC Security Scanner & AI Patch Engine</p>
            </div>
          </div>
          <div className="flex items-center space-x-2 bg-slate-900 border border-slate-800 px-4 py-1.5 rounded-full text-xs text-emerald-400">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
            <span>API Engine Online</span>
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          <section className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" /> Terraform Infrastructure Code
              </span>
              <button
                onClick={() => runScan(iacCode)}
                disabled={loading}
                className="bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-slate-950 font-semibold px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-2 cursor-pointer shadow-lg shadow-cyan-500/10"
              >
                {loading ? "Analyzing Engine..." : "Trigger AI Audit"}
              </button>
            </div>

            <textarea
              value={iacCode}
              onChange={(e) => setIacCode(e.target.value)}
              className="w-full h-[560px] bg-slate-900 border border-slate-800 rounded-xl p-4 font-mono text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 leading-relaxed"
              spellCheck="false"
            />
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
    </main>
  );
}
