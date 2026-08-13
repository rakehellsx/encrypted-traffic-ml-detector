import { PcapDropzone, toBase64 } from "@/components/PcapDropzone";
import { PageHeader } from "@/components/PageHeader";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { trpc } from "@/lib/trpc";
import { FileCheck2, Network, PackageOpen } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

export default function Upload() {
  const utils = trpc.useUtils();
  const [label, setLabel] = useState<"benign" | "malicious" | "unlabeled">("unlabeled");
  const [stage, setStage] = useState("等待选择文件");
  const [progress, setProgress] = useState(0);
  const [jobId, setJobId] = useState<number | null>(null);
  const [result, setResult] = useState<{ packetCount: number; flowCount: number; protocolDistribution: Record<string, number> } | null>(null);
  const { data: job } = trpc.datasets.uploadJob.useQuery({ jobId: jobId ?? 0 }, { enabled: Boolean(jobId), refetchInterval: 500 });
  const processUpload = trpc.datasets.processUploadJob.useMutation({ onSuccess: data => { setResult(data); setStage("解析完成，已保存数据集与流特征"); utils.datasets.list.invalidate(); utils.dashboard.overview.invalidate(); toast.success("PCAP 已解析并保存"); }, onError: error => { setStage("处理失败"); toast.error(error.message); } });
  const createUpload = trpc.datasets.createUploadJob.useMutation({ onSuccess: nextJobId => { setJobId(nextJobId); processUpload.mutate({ jobId: nextJobId }); }, onError: error => { setStage("上传失败"); toast.error(error.message); } });
  const handleUpload = async (file: File) => { setProgress(0); setResult(null); setJobId(null); setStage("正在读取文件并编码上传内容"); const fileBase64 = await toBase64(file, setProgress); setStage("正在上传文件并创建解析任务"); createUpload.mutate({ name: file.name, fileBase64, label }); };
  const activeStage = job?.status === "queued" ? "文件已存储，等待解析" : job?.status === "processing" ? (job.progress >= 75 ? "正在持久化流特征" : job.progress >= 55 ? "正在创建数据集记录" : "正在解析数据包与双向流") : job?.status === "completed" ? "解析完成" : job?.status === "failed" ? `解析失败：${job.errorMessage ?? "未知错误"}` : stage;
  const busy = createUpload.isPending || processUpload.isPending;
  return <><PageHeader eyebrow="数据接入" title="上传训练 PCAP" description="上传离线 PCAP 后，平台将解析五元组、双向流统计、SPLT 及可见 TLS/QUIC 元数据，并将特征保存为可训练数据集。" />
    <div className="grid gap-5 xl:grid-cols-[1.35fr_.65fr]"><div><div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.08] bg-white/[0.03] p-3"><div><p className="text-xs font-medium text-slate-300">初始标签</p><p className="mt-1 text-[11px] text-slate-500">训练前可在数据集管理中继续修订</p></div><Select value={label} onValueChange={value => setLabel(value as typeof label)}><SelectTrigger className="w-40 border-white/10 bg-[#081421] text-slate-200"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="unlabeled">未标注</SelectItem><SelectItem value="benign">良性</SelectItem><SelectItem value="malicious">恶意</SelectItem></SelectContent></Select></div><PcapDropzone onUpload={handleUpload} busy={busy} stage={activeStage} progress={job?.progress ?? progress} />
      <Card className="border-white/[0.08] bg-white/[0.035] p-5 text-slate-200"><p className="text-sm font-semibold text-white">上传后处理范围</p><div className="mt-4 grid gap-3 sm:grid-cols-3">{[{ icon: Network, title: "双向流统计", text: "包数、字节数、持续时间、包长、IAT 与上下行比" }, { icon: PackageOpen, title: "早期序列", text: "前 24 个数据包的长度、到达间隔与方向 SPLT" }, { icon: FileCheck2, title: "可见握手", text: "TLS 版本、JA3、SNI 可见性及 QUIC 指示" }].map(item => <div key={item.title} className="rounded-xl border border-white/[0.06] bg-[#081421]/50 p-4"><item.icon className="h-4 w-4 text-cyan-200" /><p className="mt-3 text-xs font-medium text-slate-200">{item.title}</p><p className="mt-1 text-[11px] leading-5 text-slate-500">{item.text}</p></div>)}</div></Card></div>
    <aside className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-5"><p className="text-sm font-semibold text-white">解析结果</p>{result ? <div className="mt-5 space-y-4"><div className="grid grid-cols-2 gap-3"><div className="rounded-xl bg-cyan-300/10 p-3"><p className="text-[11px] text-cyan-100/70">数据包</p><p className="mt-1 text-xl font-semibold text-cyan-100">{result.packetCount.toLocaleString()}</p></div><div className="rounded-xl bg-violet-300/10 p-3"><p className="text-[11px] text-violet-100/70">双向流</p><p className="mt-1 text-xl font-semibold text-violet-100">{result.flowCount.toLocaleString()}</p></div></div><div><p className="mb-2 text-xs text-slate-500">协议分布</p><div className="space-y-2">{Object.entries(result.protocolDistribution).filter(([, value]) => value > 0).map(([protocol, count]) => <div key={protocol} className="flex items-center justify-between rounded-lg bg-white/[0.035] px-3 py-2 text-xs"><span className="text-slate-300">{protocol}</span><Badge variant="outline" className="border-white/10 text-slate-300">{count}</Badge></div>)}</div></div></div> : <div className="grid min-h-52 place-items-center text-center"><p className="max-w-xs text-sm leading-6 text-slate-500">选择并上传一个 PCAP 文件后，此处将显示解析出的包数量、流数量和协议分布。</p></div>}</aside></div></>;
}
