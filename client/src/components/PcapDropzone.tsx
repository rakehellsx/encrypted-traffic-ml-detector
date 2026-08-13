import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { FileUp, Loader2, ShieldCheck } from "lucide-react";
import { ChangeEvent, useRef, useState } from "react";

export function toBase64(file: File, onProgress?: (percentage: number) => void) { return new Promise<string>((resolve, reject) => { const reader = new FileReader(); reader.onerror = () => reject(new Error("无法读取文件")); reader.onprogress = event => { if (event.lengthComputable) onProgress?.(Math.round(event.loaded / event.total * 100)); }; reader.onload = () => { onProgress?.(100); resolve(String(reader.result)); }; reader.readAsDataURL(file); }); }

export function PcapDropzone({ onUpload, busy, stage, progress }: { onUpload: (file: File) => Promise<void>; busy: boolean; stage?: string; progress?: number }) {
  const input = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const visibleProgress = busy ? (progress ?? 0) : file ? 100 : 0;
  const choose = (next?: File) => { if (!next) return; if (!/\.(pcap|cap)$/i.test(next.name)) { setError("请上传标准 .pcap 或 .cap 文件"); return; } if (next.size > 20 * 1024 * 1024) { setError("单个文件不能超过 20 MB"); return; } setError(null); setFile(next); };
  const handleInput = (event: ChangeEvent<HTMLInputElement>) => choose(event.target.files?.[0]);
  return <div className="rounded-2xl border border-dashed border-cyan-300/25 bg-cyan-300/[0.025] p-5 md:p-7"><input ref={input} type="file" accept=".pcap,.cap,application/vnd.tcpdump.pcap" className="hidden" onChange={handleInput} /><div onDragOver={event => { event.preventDefault(); setDragging(true); }} onDragLeave={() => setDragging(false)} onDrop={event => { event.preventDefault(); setDragging(false); choose(event.dataTransfer.files?.[0]); }} className={`grid min-h-56 place-items-center rounded-xl border transition-colors ${dragging ? "border-cyan-300 bg-cyan-300/10" : "border-white/[0.08] bg-[#081421]/50"}`}><div className="max-w-md px-5 text-center"><div className="mx-auto grid h-12 w-12 place-items-center rounded-2xl bg-cyan-300/10 text-cyan-200"><FileUp className="h-6 w-6" /></div><p className="mt-4 text-sm font-medium text-white">拖拽 PCAP 文件至此处</p><p className="mt-2 text-xs leading-5 text-slate-500">仅限离线 libpcap 以太网文件，单文件最大 20 MB。文件将在后端提取流特征后安全存储。</p><Button type="button" variant="outline" onClick={() => input.current?.click()} className="mt-5 border-white/10 bg-white/[0.04] text-slate-200 hover:bg-white/[0.08]">选择 PCAP 文件</Button></div></div>
    {error && <p className="mt-3 text-xs text-rose-300">{error}</p>}
    {file && <div className="mt-4 rounded-xl border border-white/[0.08] bg-white/[0.035] p-4"><div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center"><div><p className="text-sm font-medium text-slate-100">{file.name}</p><p className="mt-1 text-xs text-slate-500">{(file.size / 1024 / 1024).toFixed(2)} MB · 等待解析</p></div><Button disabled={busy} onClick={() => onUpload(file)} className="bg-cyan-300 text-slate-950 hover:bg-cyan-200">{busy ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />处理中</> : "开始上传与特征提取"}</Button></div>{busy && <div className="mt-4"><div className="mb-2 flex items-center justify-between text-xs text-slate-400"><span>{stage ?? "正在处理"}</span><span>{visibleProgress < 100 ? `${visibleProgress}%` : "文件读取完成"}</span></div><Progress value={visibleProgress} className="h-1.5 bg-white/10" /></div>}</div>}
    <div className="mt-4 flex items-center gap-2 text-[11px] text-slate-500"><ShieldCheck className="h-3.5 w-3.5 text-cyan-300" />仅解析包头、流统计、SPLT 与可见握手元数据；不执行任何上传文件内容。</div>
  </div>;
}
