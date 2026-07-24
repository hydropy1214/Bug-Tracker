import { useState } from 'react';
import { CheckCircle2, ChevronDown, ChevronRight, ExternalLink, Terminal } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';
import { cn } from '@/lib/utils';
import { Finding, SEV, verificationLabel } from './scan-types';

export function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const severity = SEV[finding.severity] ?? SEV.info;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className={cn(
        'rounded-md border overflow-hidden transition-all',
        severity.border,
        severity.bg,
      )}
    >
      <button
        onClick={() => setOpen((value) => !value)}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:brightness-110 transition-all"
      >
        <div className={cn('w-2 h-2 rounded-full flex-shrink-0 mt-1.5', severity.dot)} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={cn('text-[10px] font-mono font-bold tracking-widest', severity.color)}>
              {severity.label}
            </span>
            <span
              className={cn(
                'text-[10px] font-mono px-1.5 py-0.5 rounded border',
                finding.verification === 'suspected'
                  ? 'text-yellow-300 border-yellow-500/30 bg-yellow-500/10'
                  : finding.verification === 'version_match'
                    ? 'text-cyan-300 border-cyan-500/30 bg-cyan-500/10'
                    : finding.verification === 'informational'
                      ? 'text-muted-foreground border-border bg-accent'
                      : 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10',
              )}
            >
              {verificationLabel(finding.verification)}
              {finding.confidence != null ? ` · ${finding.confidence}%` : ''}
            </span>
            {finding.verified && (
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border text-primary border-primary/30 bg-primary/10">
                CANARY VERIFIED
              </span>
            )}
            {finding.cvss > 0 && (
              <span
                className={cn(
                  'text-[10px] font-mono px-1.5 py-0.5 rounded border',
                  severity.color,
                  severity.border,
                )}
              >
                CVSS {finding.cvss.toFixed(1)}
              </span>
            )}
            {finding.cve && (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${finding.cve}`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(event) => event.stopPropagation()}
                className="text-[10px] font-mono text-primary hover:underline flex items-center gap-0.5"
              >
                {finding.cve} <ExternalLink className="w-2.5 h-2.5" />
              </a>
            )}
          </div>
          <div className="font-medium text-sm text-foreground mt-0.5 leading-snug">
            {finding.title}
          </div>
        </div>
        <div className="flex-shrink-0 mt-1">
          {open ? (
            <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
          )}
        </div>
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 space-y-4 border-t border-white/5">
              <div className="pt-3">
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5">
                  Description
                </div>
                <p className="text-sm text-foreground/80 leading-relaxed">{finding.description}</p>
              </div>
              {finding.verification === 'suspected' && (
                <div className="rounded border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-[11px] font-mono text-yellow-200">
                  This is a signal requiring analyst validation — not a confirmed exploit.
                </div>
              )}
              <div>
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <Terminal className="w-3 h-3" /> Evidence / Proof
                </div>
                <pre className="text-[11px] font-mono bg-black/40 border border-white/10 rounded p-3 overflow-x-auto text-primary/90 whitespace-pre-wrap leading-relaxed max-h-64 overflow-y-auto">
                  {finding.evidence}
                </pre>
              </div>
              <div>
                <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" /> Remediation
                </div>
                <pre className="text-[11px] font-mono text-foreground/70 whitespace-pre-wrap leading-relaxed">
                  {finding.remediation}
                </pre>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px] font-mono">
                <div className="rounded border border-border/60 bg-black/20 px-2 py-1.5">
                  <span className="text-muted-foreground block uppercase">Evidence</span>
                  <span className="text-foreground">{finding.evidenceQuality ?? 'standard'}</span>
                </div>
                <div className="rounded border border-border/60 bg-black/20 px-2 py-1.5">
                  <span className="text-muted-foreground block uppercase">Repeatability</span>
                  <span className="text-foreground">
                    {finding.reproducibility?.replaceAll('_', ' ') ?? 'not tested'}
                  </span>
                </div>
                {finding.affectedParameter && (
                  <div className="rounded border border-border/60 bg-black/20 px-2 py-1.5">
                    <span className="text-muted-foreground block uppercase">Parameter</span>
                    <span className="text-foreground break-all">{finding.affectedParameter}</span>
                  </div>
                )}
                {finding.verificationMethod && (
                  <div className="rounded border border-border/60 bg-black/20 px-2 py-1.5">
                    <span className="text-muted-foreground block uppercase">Method</span>
                    <span className="text-foreground">{finding.verificationMethod}</span>
                  </div>
                )}
              </div>
              {finding.negativeTests && (
                <div>
                  <div className="text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1.5">
                    Negative Controls
                  </div>
                  <p className="text-[11px] font-mono text-foreground/70 whitespace-pre-wrap">
                    {finding.negativeTests}
                  </p>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export function SeveritySummary({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) return null;
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
        const count = findings.filter((finding) => finding.severity === severity).length;
        if (count === 0) return null;
        const config = SEV[severity]!;
        return (
          <div
            key={severity}
            className={cn(
              'flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-mono font-bold',
              config.color,
              config.bg,
              config.border,
            )}
          >
            <span className={cn('w-1.5 h-1.5 rounded-full', config.dot)} />
            {count} {config.label}
          </div>
        );
      })}
    </div>
  );
}
