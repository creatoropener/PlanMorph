/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import {
  Search,
  Copy,
  Check,
  Download,
  ChevronRight,
  ExternalLink,
  Code2,
  ShieldAlert,
  FileCode
} from 'lucide-react';
import { AUDIT_FINDINGS, REPO_FILES, Severity } from './auditData';

type ActiveSection = 'findings' | 'code-diff' | 'checklist';

export default function App() {
  const [activeSection, setActiveSection] = useState<ActiveSection>('findings');
  const [severityFilter, setSeverityFilter] = useState<'All' | Severity>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFindingId, setSelectedFindingId] = useState<string>(AUDIT_FINDINGS[0].id);
  const [selectedFilename, setSelectedFilename] = useState<string>(REPO_FILES[0].filename);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [completedChecks, setCompletedChecks] = useState<Record<string, boolean>>({});

  const filteredFindings = useMemo(() => {
    return AUDIT_FINDINGS.filter((item) => {
      const matchesSeverity = severityFilter === 'All' || item.severity === severityFilter;
      const q = searchQuery.trim().toLowerCase();
      const matchesQuery =
        !q ||
        item.title.toLowerCase().includes(q) ||
        item.id.toLowerCase().includes(q) ||
        item.cwe.toLowerCase().includes(q) ||
        item.affectedFiles.some((f) => f.toLowerCase().includes(q)) ||
        item.summary.toLowerCase().includes(q);
      return matchesSeverity && matchesQuery;
    });
  }, [severityFilter, searchQuery]);

  const activeFinding = useMemo(() => {
    return (
      filteredFindings.find((f) => f.id === selectedFindingId) ||
      filteredFindings[0] ||
      AUDIT_FINDINGS[0]
    );
  }, [filteredFindings, selectedFindingId]);

  const activeRepoFile = useMemo(() => {
    return REPO_FILES.find((f) => f.filename === selectedFilename) || REPO_FILES[0];
  }, [selectedFilename]);

  const severityCounts = useMemo(() => {
    return {
      Critical: AUDIT_FINDINGS.filter((f) => f.severity === 'Critical').length,
      High: AUDIT_FINDINGS.filter((f) => f.severity === 'High').length,
      Medium: AUDIT_FINDINGS.filter((f) => f.severity === 'Medium').length,
      Low: AUDIT_FINDINGS.filter((f) => f.severity === 'Low').length
    };
  }, []);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1800);
  };

  const handleExportMarkdown = () => {
    const lines: string[] = [
      '# Security Audit Report: creatoropener/PlanMorph (main)',
      '',
      'Repository: https://github.com/creatoropener/PlanMorph/tree/main',
      `Total Findings: ${AUDIT_FINDINGS.length} (${severityCounts.Critical} Critical, ${severityCounts.High} High, ${severityCounts.Medium} Medium, ${severityCounts.Low} Low)`,
      '',
      '---',
      ''
    ];

    for (const f of AUDIT_FINDINGS) {
      lines.push(`## [${f.id}] ${f.title}`);
      lines.push(`- **Severity:** ${f.severity}`);
      lines.push(`- **CWE / OWASP:** ${f.cwe} · ${f.owasp}`);
      lines.push(`- **Location:** ${f.lineRefs}`);
      lines.push('');
      lines.push(`### Technical Mechanics`);
      lines.push(f.mechanics);
      lines.push('');
      lines.push(`### Security Impact`);
      lines.push(f.impact);
      lines.push('');
      lines.push(`### Vulnerable Code`);
      lines.push('```javascript');
      lines.push(f.vulnerableSnippet);
      lines.push('```');
      lines.push('');
      lines.push(`### Recommended Patch`);
      lines.push('```javascript');
      lines.push(f.remediatedSnippet);
      lines.push('```');
      lines.push('');
    }

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'PlanMorph-Security-Audit-Report.md';
    a.click();
    URL.revokeObjectURL(url);
  };

  const toggleChecklist = (id: string) => {
    setCompletedChecks((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const getSeverityTextStyle = (severity: Severity) => {
    switch (severity) {
      case 'Critical':
        return 'text-rose-400 font-semibold';
      case 'High':
        return 'text-amber-400 font-semibold';
      case 'Medium':
        return 'text-sky-400 font-medium';
      case 'Low':
        return 'text-slate-300 font-medium';
    }
  };

  return (
    <div className="min-h-screen bg-[#0B0F17] text-slate-100 flex flex-col">
      {/* 3-Zone Top Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800/80 bg-[#0B0F17]/95 sticky top-0 z-30">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveSection('findings');
          }}
          className="text-base font-bold tracking-tight text-slate-100 whitespace-nowrap shrink-0"
        >
          PlanMorph Security Audit
        </a>

        {/* Zone 2: Concise single-line navigation links */}
        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-400">
          <a
            href="#findings"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('findings');
            }}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'findings' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400' : ''
            }`}
          >
            Vulnerability Findings
          </a>
          <a
            href="#code-diff"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('code-diff');
            }}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'code-diff' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400' : ''
            }`}
          >
            Hardened Source Diffs
          </a>
          <a
            href="#checklist"
            onClick={(e) => {
              e.preventDefault();
              setActiveSection('checklist');
            }}
            className={`hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 ${
              activeSection === 'checklist' ? 'text-slate-100 underline underline-offset-8 decoration-sky-400' : ''
            }`}
          >
            Remediation Checklist
          </a>
          <a
            href="https://github.com/creatoropener/PlanMorph/tree/main"
            target="_blank"
            rel="noreferrer"
            className="hover:text-slate-100 transition-colors whitespace-nowrap shrink-0 inline-flex items-center gap-1"
          >
            Target Repository
            <ExternalLink className="w-3.5 h-3.5" />
          </a>
        </nav>

        {/* Zone 3: 1 primary action */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={handleExportMarkdown}
            className="px-4 py-2 text-xs font-semibold text-slate-950 bg-sky-400 rounded-lg hover:bg-sky-300 transition-colors whitespace-nowrap shrink-0 inline-flex items-center gap-2 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Audit Report
          </button>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="flex-1 max-w-[1380px] w-full mx-auto px-6 py-8 space-y-8">
        {/* Executive Audit Overview Header */}
        <section className="border-b border-slate-800/80 pb-8">
          <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-6">
            <div className="space-y-2 max-w-3xl">
              <div className="text-xs text-slate-400 font-mono">
                github.com/creatoropener/PlanMorph · branch: main · Points 3–8 Remediated (Points 1 & 2 Excluded)
              </div>
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-50">
                PlanMorph Patch Set (Issues #3 – #8 Fixed)
              </h1>
              <p className="text-sm text-slate-300 leading-relaxed">
                All vulnerabilities in Points 3 through 8 have been remediated across <code className="text-slate-100">server.js</code>, <code className="text-slate-100">paypal.js</code>, <code className="text-slate-100">policy.js</code>, <code className="text-slate-100">agent.js</code>, <code className="text-slate-100">public/index.html</code>, <code className="text-slate-100">.env.example</code>, and <code className="text-slate-100">.gitignore</code> while preserving the unauthenticated sandbox workflow (Point 1) and simple webhook logger (Point 2).
              </p>
            </div>

            {/* Mobile section switcher */}
            <div className="flex md:hidden items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg self-start">
              <button
                onClick={() => setActiveSection('findings')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activeSection === 'findings' ? 'bg-slate-800 text-white' : 'text-slate-400'
                }`}
              >
                Findings
              </button>
              <button
                onClick={() => setActiveSection('code-diff')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activeSection === 'code-diff' ? 'bg-slate-800 text-white' : 'text-slate-400'
                }`}
              >
                Source Diffs
              </button>
              <button
                onClick={() => setActiveSection('checklist')}
                className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 ${
                  activeSection === 'checklist' ? 'bg-slate-800 text-white' : 'text-slate-400'
                }`}
              >
                Checklist
              </button>
            </div>
          </div>

          {/* 4-Column Metric Strip */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-6 pt-6 border-t border-slate-800/60">
            <div>
              <div className="text-xs text-slate-400">Remediated Issues</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono tabular-nums text-emerald-400">
                  06
                </span>
                <span className="text-xs text-slate-400">Points 3, 4, 5, 6, 7, 8 Fixed</span>
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Excluded Per Request</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono tabular-nums text-slate-400">
                  02
                </span>
                <span className="text-xs text-slate-400">Points 1 & 2 Kept As-Is</span>
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Patched Repo Files</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono tabular-nums text-sky-400">
                  06
                </span>
                <span className="text-xs text-slate-400">Zero New NPM Dependencies</span>
              </div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Default Anthropic Model</div>
              <div className="mt-1 flex items-baseline gap-2">
                <span className="text-sm font-bold font-mono tabular-nums text-slate-200">
                  claude-sonnet-4-20250514
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* SECTION 1: VULNERABILITY FINDINGS EXPLORER */}
        {activeSection === 'findings' && (
          <section className="space-y-6">
            {/* Filter & Search Bar */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              {/* Interactive Segmented Filter Control */}
              <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg self-start">
                {(['All', 'High', 'Medium', 'Low', 'Critical'] as const).map((sev) => (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(sev)}
                    className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      severityFilter === sev
                        ? 'bg-slate-800 text-slate-100 shadow-xs'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {sev}
                  </button>
                ))}
              </div>

              {/* Search Input */}
              <div className="relative w-full sm:w-80">
                <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter by point, file, CWE, or keyword..."
                  className="w-full pl-9 pr-3 py-2 text-xs bg-slate-900 border border-slate-800 rounded-lg text-slate-100 placeholder:text-slate-500 focus:outline-none focus:border-sky-400"
                />
              </div>
            </div>

            {filteredFindings.length === 0 ? (
              <div className="border border-slate-800 rounded-xl p-12 text-center space-y-3 bg-slate-900/30">
                <p className="text-sm text-slate-300">No audit findings match your current filter criteria.</p>
                <button
                  onClick={() => {
                    setSeverityFilter('All');
                    setSearchQuery('');
                  }}
                  className="px-4 py-2 text-xs font-medium text-slate-950 bg-sky-400 rounded-lg hover:bg-sky-300 transition-colors cursor-pointer"
                >
                  Reset Filters
                </button>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                {/* Left Column: High-Density Findings List (5 cols) */}
                <div className="lg:col-span-5 border border-slate-800 rounded-xl overflow-hidden bg-slate-900/30 divide-y divide-slate-800/80">
                  {filteredFindings.map((item) => {
                    const isSelected = item.id === activeFinding.id;
                    return (
                      <button
                        key={item.id}
                        onClick={() => setSelectedFindingId(item.id)}
                        className={`w-full text-left p-4 transition-colors flex items-start justify-between gap-3 cursor-pointer ${
                          isSelected ? 'bg-slate-800/70' : 'hover:bg-slate-900/80'
                        }`}
                      >
                        <div className="space-y-1.5 min-w-0">
                          {/* Unboxed metadata line with typographic separators */}
                          <div className="flex items-center gap-2 text-xs font-mono">
                            <span className="text-slate-200 font-semibold">Point {item.pointNumber}</span>
                            <span aria-hidden="true" className="text-slate-600">·</span>
                            <span className={item.status === 'Fixed' ? 'text-emerald-400 font-semibold' : 'text-slate-400'}>
                              {item.status}
                            </span>
                            <span aria-hidden="true" className="text-slate-600">·</span>
                            <span className={getSeverityTextStyle(item.severity)}>{item.severity}</span>
                          </div>
                          <h2 className="text-sm font-semibold text-slate-100 leading-snug">
                            {item.title}
                          </h2>
                          <div className="text-xs text-slate-400 font-mono truncate">
                            {item.lineRefs}
                          </div>
                        </div>
                        <ChevronRight
                          className={`w-4 h-4 shrink-0 mt-1 transition-transform ${
                            isSelected ? 'text-sky-400 translate-x-0.5' : 'text-slate-600'
                          }`}
                        />
                      </button>
                    );
                  })}
                </div>

                {/* Right Column: Detailed Finding Inspector (7 cols) */}
                <div className="lg:col-span-7 border border-slate-800 rounded-xl p-6 bg-slate-900/30 space-y-6">
                  <div className="border-b border-slate-800 pb-5 space-y-2">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400">
                      <span className="text-slate-200 font-semibold">
                        Point {activeFinding.pointNumber} ({activeFinding.id})
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className={activeFinding.status === 'Fixed' ? 'text-emerald-400 font-semibold' : 'text-slate-400'}>
                        {activeFinding.status}
                      </span>
                      <span aria-hidden="true">·</span>
                      <span className={getSeverityTextStyle(activeFinding.severity)}>
                        {activeFinding.severity} Severity
                      </span>
                      <span aria-hidden="true">·</span>
                      <span>{activeFinding.cwe}</span>
                    </div>
                    <h2 className="text-xl font-bold text-slate-50 leading-snug">
                      {activeFinding.title}
                    </h2>
                    <div className="text-xs font-mono text-slate-400">
                      Location: <span className="text-slate-200">{activeFinding.lineRefs}</span>
                    </div>
                  </div>

                  {/* Mechanics & Impact */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <h3 className="text-xs font-semibold text-slate-300">
                        Vulnerability Mechanics
                      </h3>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {activeFinding.mechanics}
                      </p>
                    </div>
                    <div className="space-y-2">
                      <h3 className="text-xs font-semibold text-slate-300">
                        Remediation Impact
                      </h3>
                      <p className="text-sm text-slate-300 leading-relaxed">
                        {activeFinding.impact}
                      </p>
                    </div>
                  </div>

                  {/* Vulnerable Code Block */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-rose-400">
                        Original Implementation ({activeFinding.affectedFiles.join(', ')})
                      </span>
                    </div>
                    <pre className="p-4 rounded-lg bg-[#070A0F] border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed">
                      <code>{activeFinding.vulnerableSnippet}</code>
                    </pre>
                  </div>

                  {/* Remediated Code Block */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-emerald-400">
                        Applied Fix
                      </span>
                      <button
                        onClick={() =>
                          handleCopy(activeFinding.remediatedSnippet, `patch-${activeFinding.id}`)
                        }
                        className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-800 rounded-md transition-colors inline-flex items-center gap-1.5 cursor-pointer"
                      >
                        {copiedId === `patch-${activeFinding.id}` ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            Copied
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            Copy Patch
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="p-4 rounded-lg bg-[#070A0F] border border-slate-800 text-xs font-mono text-emerald-100 overflow-x-auto leading-relaxed">
                      <code>{activeFinding.remediatedSnippet}</code>
                    </pre>
                  </div>

                  {/* Actionable Remediation Steps */}
                  <div className="space-y-2 pt-2 border-t border-slate-800/80">
                    <h3 className="text-xs font-semibold text-slate-300">
                      Changes Applied for Point {activeFinding.pointNumber}
                    </h3>
                    <ul className="space-y-2">
                      {activeFinding.remediationSteps.map((step, idx) => (
                        <li key={idx} className="text-sm text-slate-300 flex items-start gap-2.5">
                          <span className="font-mono text-xs text-sky-400 mt-0.5">
                            0{idx + 1}.
                          </span>
                          <span>{step}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        {/* SECTION 2: SIDE-BY-SIDE HARDENED SOURCE FILES */}
        {activeSection === 'code-diff' && (
          <section className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-lg overflow-x-auto">
                {REPO_FILES.map((file) => (
                  <button
                    key={file.filename}
                    onClick={() => setSelectedFilename(file.filename)}
                    className={`px-3 py-1.5 text-xs font-mono font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                      selectedFilename === file.filename
                        ? 'bg-slate-800 text-slate-100'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {file.filename}
                  </button>
                ))}
              </div>

              <button
                onClick={() =>
                  handleCopy(activeRepoFile.hardenedCode, `file-${activeRepoFile.filename}`)
                }
                className="px-4 py-2 text-xs font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors whitespace-nowrap shrink-0 inline-flex items-center gap-2 self-start cursor-pointer"
              >
                {copiedId === `file-${activeRepoFile.filename}` ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    Copied Hardened {activeRepoFile.filename}
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    Copy Hardened {activeRepoFile.filename}
                  </>
                )}
              </button>
            </div>

            {/* Summary of changes for this file */}
            <div className="border border-slate-800 rounded-xl p-5 bg-slate-900/30 space-y-3">
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400">
                <FileCode className="w-4 h-4 text-sky-400" />
                <span className="text-slate-100 font-semibold">{activeRepoFile.filename}</span>
                <span aria-hidden="true">·</span>
                <span>{activeRepoFile.role}</span>
                <span aria-hidden="true">·</span>
                <span className="text-emerald-400">
                  {activeRepoFile.pointsFixed} addressed
                </span>
              </div>
              <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1">
                {activeRepoFile.notes.map((note, idx) => (
                  <li key={idx} className="text-xs text-slate-300 flex items-start gap-2">
                    <span className="font-mono text-sky-400">0{idx + 1}.</span>
                    <span>{note}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Side-by-Side Code View */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="border border-slate-800 rounded-xl overflow-hidden bg-[#070A0F]">
                <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
                  <span className="text-xs font-mono text-rose-400 font-medium">
                    Original: {activeRepoFile.filename} (main)
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    {activeRepoFile.originalCode.split('\n').length} lines
                  </span>
                </div>
                <pre className="p-4 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed max-h-[640px]">
                  <code>{activeRepoFile.originalCode}</code>
                </pre>
              </div>

              <div className="border border-slate-800 rounded-xl overflow-hidden bg-[#070A0F]">
                <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
                  <span className="text-xs font-mono text-emerald-400 font-medium">
                    Hardened: {activeRepoFile.filename} (patched)
                  </span>
                  <span className="text-xs font-mono text-slate-400">
                    {activeRepoFile.hardenedCode.split('\n').length} lines
                  </span>
                </div>
                <pre className="p-4 text-xs font-mono text-emerald-100 overflow-x-auto leading-relaxed max-h-[640px]">
                  <code>{activeRepoFile.hardenedCode}</code>
                </pre>
              </div>
            </div>
          </section>
        )}

        {/* SECTION 3: INTERACTIVE REMEDIATION TRACKER */}
        {activeSection === 'checklist' && (
          <section className="space-y-6">
            <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-900/30">
              <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-slate-100">
                    Prioritized Hardening Roadmap
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Track remediation progress across all {AUDIT_FINDINGS.length} identified vulnerabilities before switching from PayPal Sandbox to Live.
                  </p>
                </div>
                <div className="text-xs font-mono tabular-nums text-slate-300">
                  {Object.values(completedChecks).filter(Boolean).length} / {AUDIT_FINDINGS.length} Resolved
                </div>
              </div>

              <div className="divide-y divide-slate-800/80">
                {AUDIT_FINDINGS.map((finding) => {
                  const checked = !!completedChecks[finding.id];
                  return (
                    <div
                      key={finding.id}
                      className="px-6 py-4 flex items-start justify-between gap-4 hover:bg-slate-900/60 transition-colors"
                    >
                      <label className="flex items-start gap-3.5 cursor-pointer flex-1">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleChecklist(finding.id)}
                          className="mt-1 w-4 h-4 rounded border-slate-700 bg-slate-900 text-sky-400 focus:ring-sky-400 cursor-pointer"
                        />
                        <div className="space-y-1">
                          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                            <span className="text-slate-300">{finding.id}</span>
                            <span aria-hidden="true" className="text-slate-600">·</span>
                            <span className={getSeverityTextStyle(finding.severity)}>
                              {finding.severity}
                            </span>
                            <span aria-hidden="true" className="text-slate-600">·</span>
                            <span className="text-slate-400">{finding.lineRefs}</span>
                          </div>
                          <div
                            className={`text-sm font-semibold ${
                              checked ? 'line-through text-slate-500' : 'text-slate-100'
                            }`}
                          >
                            {finding.title}
                          </div>
                          <p className="text-xs text-slate-400">{finding.summary}</p>
                        </div>
                      </label>

                      <button
                        onClick={() => {
                          setSelectedFindingId(finding.id);
                          setActiveSection('findings');
                        }}
                        className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800/80 hover:bg-slate-800 rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                      >
                        View Patch
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          </section>
        )}
      </main>

      {/* Quiet Footer */}
      <footer className="border-t border-slate-800/80 px-6 py-5 text-xs text-slate-500">
        <div className="max-w-[1380px] mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div>PlanMorph Security Audit Workbench · Target: creatoropener/PlanMorph (main)</div>
          <div className="font-mono">8 Findings Identified · Defensive Code Review</div>
        </div>
      </footer>
    </div>
  );
}
