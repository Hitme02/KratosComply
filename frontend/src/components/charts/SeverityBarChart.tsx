import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { useReportStore } from "@/hooks/useReportStore";

const COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#facc15",
  low: "#3b82f6",
};

export function SeverityBarChart() {
  const { report } = useReportStore();
  if (!report) return null;

  const data = [
    { name: "Critical", value: report.metrics.critical, color: COLORS.critical },
    { name: "High", value: report.metrics.high, color: COLORS.high },
    { name: "Medium", value: report.metrics.medium, color: COLORS.medium },
    { name: "Low", value: report.metrics.low, color: COLORS.low },
  ];

  return (
    <div className="rounded-2xl border border-border/60 bg-card/60 p-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold text-muted-foreground">Severity Breakdown</p>
      </div>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <XAxis dataKey="name" stroke="#94a3b8" axisLine={false} tickLine={false} />
            <YAxis stroke="#94a3b8" axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }}
              cursor={{ fill: "rgba(148, 163, 184, 0.15)" }}
            />
            <Bar dataKey="value" radius={[8, 8, 8, 8]}>
              {data.map((entry) => (
                <Cell key={entry.name} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
