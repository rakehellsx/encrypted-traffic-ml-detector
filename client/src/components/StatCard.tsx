import { LucideIcon } from "lucide-react";

export function StatCard({ label, value, detail, icon: Icon, tone = "cyan" }: { label: string; value: string | number; detail: string; icon: LucideIcon; tone?: "cyan" | "violet" | "amber" }) {
  const tones = { cyan: "bg-cyan-300/10 text-cyan-200", violet: "bg-violet-400/10 text-violet-200", amber: "bg-amber-300/10 text-amber-200" };
  return <div className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-5 shadow-[0_16px_45px_rgba(0,0,0,.12)]"><div className="flex items-start justify-between"><div><p className="text-xs font-medium text-slate-400">{label}</p><p className="mt-3 text-3xl font-semibold tracking-tight text-white">{value}</p></div><div className={`grid h-10 w-10 place-items-center rounded-xl ${tones[tone]}`}><Icon className="h-5 w-5" /></div></div><p className="mt-4 border-t border-white/[0.06] pt-3 text-xs text-slate-500">{detail}</p></div>;
}
