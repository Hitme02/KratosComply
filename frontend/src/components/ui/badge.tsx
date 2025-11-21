import { cn } from "@/lib/utils";

export function Badge({
  children,
  variant = "default",
  className,
}: {
  children: React.ReactNode;
  variant?: "default" | "outline" | "success" | "critical";
  className?: string;
}) {
  const variants: Record<string, string> = {
    default: "bg-secondary/60 text-secondary-foreground",
    outline: "border border-border/70 text-muted-foreground",
    success: "bg-emerald-500/20 text-emerald-300",
    critical: "bg-red-500/20 text-red-300",
  };
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-semibold", variants[variant], className)}>
      {children}
    </span>
  );
}
