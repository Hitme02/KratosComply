import { cn } from "@/lib/utils";

export function Badge({
  children,
  variant = "default",
  className,
}: {
  children: React.ReactNode;
  variant?: "default" | "outline" | "secondary" | "success" | "critical";
  className?: string;
}) {
  const variants: Record<string, string> = {
    default: "bg-secondary/80 text-secondary-foreground font-medium",
    outline: "border border-border/80 text-foreground/90 font-medium",
    secondary: "bg-muted/80 text-foreground/90 font-medium",
    success: "bg-emerald-500/25 text-emerald-200 font-semibold",
    critical: "bg-red-500/25 text-red-200 font-semibold",
  };
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs", variants[variant], className)}>
      {children}
    </span>
  );
}
