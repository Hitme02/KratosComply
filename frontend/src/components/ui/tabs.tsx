import { cn } from "@/lib/utils";

export interface TabsProps {
  tabs: { id: string; label: string }[];
  value: string;
  onChange: (value: string) => void;
  className?: string;
}

export function Tabs({ tabs, value, onChange, className }: TabsProps) {
  return (
    <div className={cn("flex gap-3", className)}>
      {tabs.map((tab) => (
        <button
          key={tab.id}
          onClick={() => onChange(tab.id)}
          className={cn(
            "rounded-full px-4 py-1 text-sm font-medium transition",
            value === tab.id
              ? "bg-primary text-primary-foreground shadow"
              : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
          )}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}
