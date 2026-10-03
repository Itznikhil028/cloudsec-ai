"use client";

import { useState } from "react";
import { ShieldAlert, ShieldCheck, Terminal, Code } from "lucide-react";

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

  const handleScan = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://127.0.0.1:8000/api/v1/scans/submit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          project_name: "Production-Audit",
          raw_iac_code: iacCode,
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
                onClick={handleScan}
                disabled={loading}
                className="bg-cyan-500 hover:bg-cyan-600 disabled:opacity-50 text-slate-950 font-semibold px-4 py-2 rounded-lg text-sm transition-colors flex items-center gap-2"
              >
                {loading ? "Analyzing Engine..." : "Trigger AI Audit"}
              </button>
            </div>

            <textarea
              value={iacCode}
              onChange={(e) => setIacCode(e.target.value)}
              className="w-full h-[540px] bg-slate-900 border border-slate-800 rounded-xl p-4 font-mono text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              spellCheck="false"
            />
          </section>

          <section className="space-y-4">
            <div className="flex justify-between items-center">
              <span className="text-sm font-semibold text-slate-300 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" /> Audit Findings & Patches
              </span>
              {scanResult && (
                <span className="text-xs bg-rose-500/20 text-rose-300 border border-rose-500/30 px-3 py-1 rounded-full font-medium">
                  {scanResult.total_findings} Misconfigurations Detected
                </span>
              )}
            </div>

            <div className="h-[540px] overflow-y-auto space-y-4 pr-1">
              {!scanResult ? (
                <div className="h-full border border-dashed border-slate-800 rounded-xl flex flex-col items-center justify-center text-slate-500 space-y-3">
                  <Code className="w-10 h-10 stroke-[1.5]" />
                  <p className="text-sm">Submit Terraform code on the left to run security analysis.</p>
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
                      <div className="space-y-1">
                        <p className="text-xs text-emerald-400 font-semibold">AI Automated Remediation Patch:</p>
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
