import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { trpc } from "@/lib/trpc";
import { BrainCircuit, CheckCircle2, Loader2, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

const upstreamFeatures = [
  "avg_cert_path", "avg_cert_valid_day", "avg_domain_name_length", "avg_duration", "avg_IPs_in_DNS", "avg_pkts", "avg_size", "avg_time_diff", "avg_TTL", "avg_valid_cert_percent",
  "cert_key_type", "cert_sig_alg", "cipher_suite_server", "is_CNs_in_SNA_dns", "is_O_in_issuer", "is_O_in_subject", "is_ST_in_subject", "max_duration", "max_time_diff", "number_of_domains_in_cert",
  "number_of_flows", "packet_loss", "recv_sent_pkts_ratio", "recv_sent_size_ratio", "ssl_version", "std_domain_name_length", "std_time_diff", "subject_only_CN", "resumed", "SNI_ssl_ratio",
] as const;
const featureLabels: Record<(typeof upstreamFeatures)[number], string> = {
  avg_cert_path: "证书链长度", avg_cert_valid_day: "证书有效天数", avg_domain_name_length: "域名长度", avg_duration: "平均持续时间", avg_IPs_in_DNS: "DNS IP 数", avg_pkts: "平均包数", avg_size: "平均字节数", avg_time_diff: "平均间隔", avg_TTL: "DNS TTL", avg_valid_cert_percent: "证书有效期位置",
  cert_key_type: "证书密钥类型", cert_sig_alg: "证书签名算法", cipher_suite_server: "服务端密码套件", is_CNs_in_SNA_dns: "CN/SAN 一致性", is_O_in_issuer: "签发者组织", is_O_in_subject: "主题组织", is_ST_in_subject: "主题省份", max_duration: "最大持续时间", max_time_diff: "最大间隔", number_of_domains_in_cert: "证书域名数",
  number_of_flows: "元组连接数", packet_loss: "丢失字节", recv_sent_pkts_ratio: "收发包比", recv_sent_size_ratio: "收发字节比", ssl_version: "TLS 版本", std_domain_name_length: "域名长度波动", std_time_diff: "间隔波动", subject_only_CN: "主题仅 CN", resumed: "TLS 恢复", SNI_ssl_ratio: "可见 SNI 比例",
};

export default function Training() {
  const utils = trpc.useUtils();
  const { data: datasets = [] } = trpc.datasets.list.useQuery();
  const { data: annotationSetResults = [] } = trpc.annotationSets.list.useQuery();
  const annotationSets = annotationSetResults.filter(set => set.isActive);
  const [annotationSetId, setAnnotationSetId] = useState<number | undefined>();
  const annotationSet = annotationSets.find(set => set.id === annotationSetId) ?? annotationSets.find(set => set.isDefault) ?? annotationSets[0] ?? null;
  useEffect(() => { if (!annotationSetId && annotationSet?.id) setAnnotationSetId(annotationSet.id); }, [annotationSetId, annotationSet]);
  const labels = annotationSet?.labels.filter(label => label.enabled) ?? [];
  const labelNames = Object.fromEntries(labels.map(label => [label.key, label.name]));
  const eligible = datasets.filter(dataset => dataset.trafficClass !== "unlabeled" && (!annotationSet?.id || dataset.annotationSetId === annotationSet.id));
  const [selected, setSelected] = useState<number[]>([]);
  const [algorithm, setAlgorithm] = useState<"abonnen_random_forest" | "abonnen_gbdt">("abonnen_random_forest");
  const [jobId, setJobId] = useState<number | null>(null);
  const [result, setResult] = useState<{ versionName: string; classes: string[]; metrics: { accuracy: number; precision: number; recall: number; f1: number }; trainingCount: number; validationCount: number } | null>(null);
  const train = trpc.models.train.useMutation({ onSuccess: data => { setResult(data); utils.models.list.invalidate(); utils.dashboard.overview.invalidate(); toast.success(`训练完成，已保存 ${data.versionName}`); }, onError: error => toast.error(error.message) });
  const createJob = trpc.models.createTrainingJob.useMutation({ onSuccess: (nextJobId, variables) => { setJobId(nextJobId); train.mutate({ ...variables, jobId: nextJobId }); }, onError: error => toast.error(error.message) });
  const { data: job } = trpc.models.trainingJob.useQuery({ jobId: jobId ?? 0 }, { enabled: Boolean(jobId), refetchInterval: 500 });
  const selectedClasses = useMemo(() => Array.from(new Set(selected.map(id => datasets.find(dataset => dataset.id === id)?.trafficClass).filter((value): value is string => Boolean(value && value !== "unlabeled")))), [datasets, selected]);
  const toggleDataset = (id: number) => setSelected(previous => previous.includes(id) ? previous.filter(value => value !== id) : [...previous, id]);
  const start = () => {
    if (!annotationSet?.id) return toast.error("请先选择标注集");
    const normalKey = labels.find(label => label.isNormal)?.key;
    if (!normalKey || !selectedClasses.includes(normalKey) || selectedClasses.length < 3) return toast.error("所选数据需包含正常类别和至少两种恶意类别");
    setResult(null); setJobId(null);
    createJob.mutate({ datasetIds: selected, annotationSetId: annotationSet.id, features: [...upstreamFeatures], algorithm });
  };
  const algorithmTitle = algorithm === "abonnen_random_forest" ? "Abonnen 随机森林" : "Abonnen GBDT";
  return <><PageHeader eyebrow="模型训练" title="模型训练" description="使用 Abonnen/Malicious_TLS_Detection 的 Zeek TLS 特征和原始分类算法训练多分类模型；每个版本保存标注集与类别概率契约。" />
    <div className="grid gap-5 xl:grid-cols-[1fr_.9fr]"><div className="space-y-5"><section className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-5"><div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-center"><div><p className="text-sm font-semibold text-white">1. 选择标注集与训练数据</p><p className="mt-1 text-xs text-slate-500">仅显示与所选标注集关联的已标注数据集；建议覆盖全部五种类别。</p></div><Select value={annotationSet?.id?.toString()} onValueChange={value => { setAnnotationSetId(Number(value)); setSelected([]); }}><SelectTrigger className="w-52 border-white/10 bg-[#081421] text-slate-200"><SelectValue placeholder="选择标注集" /></SelectTrigger><SelectContent>{annotationSets.filter(set => set.labels.some(label => label.enabled)).map(set => <SelectItem key={set.id} value={String(set.id)}>{set.name}</SelectItem>)}</SelectContent></Select></div><p className="mt-3 text-xs text-cyan-200">{selectedClasses.length ? selectedClasses.map(value => labelNames[value] ?? value).join(" · ") : "尚未选择类别"}</p><div className="mt-4 space-y-2">{eligible.length ? eligible.map(dataset => <label key={dataset.id} className="flex cursor-pointer items-center gap-3 rounded-xl border border-white/[0.06] bg-[#081421]/50 p-3 hover:border-cyan-300/20"><Checkbox checked={selected.includes(dataset.id)} onCheckedChange={() => toggleDataset(dataset.id)} /><span className="flex-1"><span className="block text-sm text-slate-200">{dataset.name}</span><span className="mt-1 block text-[11px] text-slate-500">{dataset.flowCount} 条流 · {labelNames[dataset.trafficClass] ?? dataset.trafficClass}</span></span><span className="rounded-full bg-cyan-300/10 px-2 py-1 text-[10px] text-cyan-100">{labelNames[dataset.trafficClass] ?? dataset.trafficClass}</span></label>) : <p className="rounded-xl border border-dashed border-white/10 p-5 text-center text-sm text-slate-500">当前标注集没有可训练数据。请先上传并完成标注。</p>}</div></section>
      <section className="rounded-2xl border border-white/[0.08] bg-white/[0.035] p-5"><p className="text-sm font-semibold text-white">2. 配置训练参数</p><div className="mt-4 rounded-xl border border-cyan-300/15 bg-cyan-300/[0.06] p-3"><div className="flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-cyan-200" /><p className="text-sm font-medium text-cyan-100">Abonnen/Malicious_TLS_Detection 核心引擎</p></div><p className="mt-1 text-xs leading-5 text-slate-400">固定使用 Zeek 连接、TLS、X.509 和 DNS 日志聚合的 30 项上游筛选特征；NFStream 仅作为并联证据展示。</p></div><div className="mt-4"><p className="mb-2 text-xs text-slate-500">分类算法</p><Select value={algorithm} onValueChange={value => setAlgorithm(value as typeof algorithm)}><SelectTrigger className="border-white/10 bg-[#081421] text-slate-200"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="abonnen_random_forest">随机森林（上游参数）</SelectItem><SelectItem value="abonnen_gbdt">GBDT（上游参数）</SelectItem></SelectContent></Select></div><div className="mt-5"><p className="mb-2 text-xs text-slate-500">固定上游特征集（30 项，训练与推理顺序一致）</p><div className="grid gap-2 sm:grid-cols-2">{upstreamFeatures.map(feature => <div key={feature} className="rounded-lg border border-white/[0.06] bg-[#081421]/50 px-3 py-2.5 text-xs text-slate-300"><span className="text-cyan-200">{featureLabels[feature]}</span><span className="ml-2 text-[10px] text-slate-500">{feature}</span></div>)}</div></div></section></div>
      <aside className="rounded-2xl border border-cyan-300/15 bg-gradient-to-b from-cyan-300/[0.08] to-white/[0.025] p-5"><div className="flex items-center gap-3"><div className="grid h-10 w-10 place-items-center rounded-xl bg-cyan-300 text-slate-950"><BrainCircuit className="h-5 w-5" /></div><div><p className="text-sm font-semibold text-white">训练执行</p><p className="text-xs text-slate-500">{algorithmTitle} · 五类概率输出</p></div></div><Button disabled={train.isPending || createJob.isPending || !eligible.length} onClick={start} className="mt-6 w-full bg-cyan-300 text-slate-950 hover:bg-cyan-200">{train.isPending || createJob.isPending ? <><Loader2 className="mr-2 h-4 w-4 animate-spin" />正在训练</> : <><SlidersHorizontal className="mr-2 h-4 w-4" />开始训练并保存版本</>}</Button>{(train.isPending || createJob.isPending) && <div className="mt-5"><div className="mb-2 flex justify-between text-xs text-slate-400"><span>{job?.progress && job.progress >= 60 ? "模型拟合与验证评估" : job?.progress && job.progress >= 30 ? "已加载上游 TLS 特征" : "正在创建训练任务"}</span><span>{job?.progress ?? 10}%</span></div><Progress value={job?.progress ?? 10} className="h-1.5 bg-white/10" /></div>}{result ? <div className="mt-6 rounded-xl border border-emerald-400/15 bg-emerald-400/[0.07] p-4"><div className="flex items-center gap-2 text-emerald-200"><CheckCircle2 className="h-4 w-4" /><span className="text-sm font-medium">已保存 {result.versionName}</span></div><div className="mt-4 grid grid-cols-2 gap-2">{Object.entries(result.metrics).map(([key, value]) => <div key={key} className="rounded-lg bg-black/15 p-2.5"><p className="text-[10px] uppercase text-emerald-100/60">{key}</p><p className="mt-1 text-lg font-semibold text-emerald-100">{(Number(value) * 100).toFixed(1)}%</p></div>)}</div><p className="mt-3 text-[11px] text-emerald-100/60">训练 {result.trainingCount} 条流 · 验证 {result.validationCount} 条流</p></div> : <p className="mt-6 text-xs leading-5 text-slate-500">模型会保存上游特征集、类别词典、标注集快照、训练数据引用、模型工件和评估指标。</p>}</aside></div></>;
}
