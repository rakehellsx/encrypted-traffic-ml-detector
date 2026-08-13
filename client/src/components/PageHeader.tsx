import { Button } from "@/components/ui/button";
import { ChevronRight } from "lucide-react";
import { ReactNode } from "react";

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="mb-7 flex flex-col gap-4 md:flex-row md:items-end md:justify-between"><div><div className="mb-2 flex items-center gap-1 text-[11px] font-medium uppercase tracking-[0.16em] text-cyan-300/75"><span>TrafficGuard</span><ChevronRight className="h-3 w-3" /><span>{eyebrow}</span></div><h1 className="text-2xl font-semibold tracking-tight text-white md:text-3xl">{title}</h1><p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">{description}</p></div>{action}</div>;
}

export function GhostAction({ children, onClick }: { children: ReactNode; onClick?: () => void }) { return <Button variant="outline" onClick={onClick} className="border-white/10 bg-white/[0.03] text-slate-200 hover:bg-white/[0.08] hover:text-white">{children}</Button>; }
