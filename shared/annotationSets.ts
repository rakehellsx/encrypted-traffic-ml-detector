export const AVAILABLE_ANNOTATION_KEYS = ["benign", "c2_channel", "data_exfiltration", "lateral_movement", "malware_transfer"] as const;
export type AnnotationKey = (typeof AVAILABLE_ANNOTATION_KEYS)[number];

export type AnnotationLabel = {
  key: AnnotationKey;
  name: string;
  description?: string;
  enabled: boolean;
  isNormal: boolean;
};

export type AnnotationSetSnapshot = {
  id?: number;
  name: string;
  description?: string;
  labels: AnnotationLabel[];
  isActive?: boolean;
  isDefault?: boolean;
};

export const DEFAULT_ANNOTATION_LABELS: AnnotationLabel[] = [
  { key: "benign", name: "正常流量", description: "正常业务与基线流量", enabled: true, isNormal: true },
  { key: "c2_channel", name: "命令控制", description: "命令与控制通信", enabled: true, isNormal: false },
  { key: "data_exfiltration", name: "数据外传", description: "疑似数据外传流量", enabled: true, isNormal: false },
  { key: "lateral_movement", name: "横向移动", description: "内部横向传播或移动", enabled: true, isNormal: false },
  { key: "malware_transfer", name: "恶意传输", description: "恶意载荷或可疑文件传输", enabled: true, isNormal: false },
];

export function labelName(snapshot: AnnotationSetSnapshot | null | undefined, key: string) {
  return snapshot?.labels.find(label => label.key === key)?.name ?? key;
}
