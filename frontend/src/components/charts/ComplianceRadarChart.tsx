import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip } from "recharts";

import { useReportStore } from "@/hooks/useReportStore";

export function ComplianceRadarChart() {
  const { report } = useReportStore();
  if (!report) return null;

  // Calculate framework readiness based on actual control states
  const controlStatesMap = report.control_states || {};
  const systemEvidence = report.system_evidence || [];
  
  // Group controls by framework
  const frameworkStats: Record<string, { total: number; satisfied: number }> = {};
  
  // Initialize frameworks from standards
  report.standards.forEach((fw) => {
    frameworkStats[fw] = { total: 0, satisfied: 0 };
  });
  
  // Count from control_states
  Object.entries(controlStatesMap).forEach(([controlId, state]: [string, any]) => {
    // Extract framework from control_id (format: "SOC2-CC6.1" or just framework name)
    const framework = controlId.includes("-") ? controlId.split("-")[0] : 
                      report.standards.find(fw => controlId.includes(fw)) || report.standards[0];
    
    if (frameworkStats[framework]) {
      frameworkStats[framework].total++;
      if (state === "VERIFIED_MACHINE" || state === "VERIFIED_SYSTEM" || state === "ATTESTED_HUMAN") {
        frameworkStats[framework].satisfied++;
      }
    }
  });
  
  // Count from system evidence
  systemEvidence.forEach((ev: any) => {
    const framework = ev.framework;
    if (frameworkStats[framework]) {
      frameworkStats[framework].total++;
      if (ev.evidence_present && !ev.expiry_detected) {
        frameworkStats[framework].satisfied++;
      }
    }
  });
  
  // Fallback: use findings if no control_states
  if (Object.keys(controlStatesMap).length === 0 && systemEvidence.length === 0) {
    report.findings.forEach((finding) => {
      finding.compliance_frameworks_affected?.forEach((fw) => {
        if (frameworkStats[fw]) {
          frameworkStats[fw].total++;
          if (finding.control_pass_fail_status === "PASS") {
            frameworkStats[fw].satisfied++;
          }
        }
      });
    });
  }
  
  // Calculate coverage percentage for each framework
  const data = report.standards.map((standard) => {
    const stats = frameworkStats[standard] || { total: 0, satisfied: 0 };
    const coverage = stats.total > 0 
      ? Math.round((stats.satisfied / stats.total) * 100)
      : 100; // Default to 100% if no controls found (optimistic)
    
    return {
      standard,
      coverage: Math.min(100, Math.max(0, coverage)),
    };
  });

  return (
    <div className="rounded-2xl border border-border/60 bg-card/60 p-4">
      <p className="text-sm font-semibold text-muted-foreground">Compliance Coverage</p>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <RadarChart data={data} outerRadius="80%">
            <PolarGrid stroke="#1f2937" />
            <PolarAngleAxis dataKey="standard" stroke="#94a3b8" tickLine={false} />
            <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }} />
            <Radar
              name="Coverage"
              dataKey="coverage"
              stroke="#a855f7"
              fill="url(#radarGradient)"
              fillOpacity={0.6}
              strokeWidth={2}
            />
            <defs>
              <linearGradient id="radarGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#a855f7" stopOpacity={0.8} />
                <stop offset="95%" stopColor="#6366f1" stopOpacity={0.3} />
              </linearGradient>
            </defs>
          </RadarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
