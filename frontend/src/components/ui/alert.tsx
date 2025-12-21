import { cn } from "@/lib/utils";
import { AlertTriangle, CheckCircle2 } from "lucide-react";

export function Alert({
  type = "info",
  title,
  description,
  className,
}: {
  type?: "info" | "success" | "error";
  title: string;
  description?: string;
  className?: string;
}) {
  const icons = {
    info: <AlertTriangle className="h-4 w-4 text-amber-400" />,
    success: <CheckCircle2 className="h-4 w-4 text-emerald-400" />,
    error: <AlertTriangle className="h-4 w-4 text-red-400" />,
  };
  return (
    <div
      className={cn(
        "flex items-start gap-3 rounded-xl border border-border/70 bg-muted/40 p-4 text-sm",
        className
      )}
    >
      {icons[type]}
      <div>
        <p className="font-bold text-foreground">{title}</p>
        {description && <p className="text-foreground/80">{description}</p>}
      </div>
    </div>
  );
}
