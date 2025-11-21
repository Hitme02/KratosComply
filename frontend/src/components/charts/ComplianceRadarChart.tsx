import { PolarAngleAxis, PolarGrid, Radar, RadarChart, ResponsiveContainer, Tooltip } from "recharts";

import { useReportStore } from "@/hooks/useReportStore";

export function ComplianceRadarChart() {
  const { report } = useReportStore();
  if (!report) return null;

  const base = Math.max(40, 100 - report.metrics.risk_score / 1.5);
  const data = report.standards.map((standard, index) => ({
    standard,
    coverage: Math.min(100, Math.round(base + index * 5)),
  }));

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
