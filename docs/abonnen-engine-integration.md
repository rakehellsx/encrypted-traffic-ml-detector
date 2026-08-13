# Abonnen 恶意 TLS 检测引擎集成设计

## 目标

本平台以 [Abonnen/Malicious_TLS_Detection](https://github.com/Abonnen/Malicious_TLS_Detection) 为唯一的加密流量监督检测引擎来源，移除既有 LightGBM + KitNET 融合模型。平台保留其基于 Zeek `conn.log`、`ssl.log`、`x509.log` 与 `dns.log` 的连接元组聚合语义、原始 30 个筛选特征，以及随机森林/GBDT 分类器实现；NFStream 继续作为并联的展示与溯源信息，不替代模型输入。

## 上游实现基线

| 层次 | 上游实现 | 平台集成规则 |
| --- | --- | --- |
| 原始解析 | Zeek 对 PCAP 生成 `conn.log`、`ssl.log`、`x509.log`、`dns.log` | 生产镜像安装 Zeek；上传、训练和检测均使用同一解析路径。 |
| 聚合单元 | `(orig_h, resp_h, resp_p, proto)` 连接元组 | 每个元组产出一行模型特征；平台保留最先出现的五元组为详情索引。 |
| 特征 | 上游 `Dataset.py` 固定的 30 项筛选特征 | 训练工件持久化特征名、类别名和类别编码；推理严格按工件特征顺序构造矩阵。 |
| 模型 | `RandomForestClassifier(n_estimators=100, max_depth=30, random_state=1024)` 与上游 GBDT 参数 | 暴露 `abonnen_random_forest` 和 `abonnen_gbdt` 两种版本；默认随机森林。 |
| 概率 | sklearn/LightGBM `predict_proba` | 将二分类实现扩展为五分类的标签编码；按 `model.classes_` 映射到平台固定五标签并补零。 |

> 多分类扩展仅改变标签编码、分层切分、指标统计和概率映射；不会替换上游的 Zeek 特征、筛选特征或分类器算法与关键参数。

## 特征适配

上游模型最终使用以下 30 个字段：

`avg_cert_path`、`avg_cert_valid_day`、`avg_domain_name_length`、`avg_duration`、`avg_IPs_in_DNS`、`avg_pkts`、`avg_size`、`avg_time_diff`、`avg_TTL`、`avg_valid_cert_percent`、`cert_key_type`、`cert_sig_alg`、`cipher_suite_server`、`is_CNs_in_SNA_dns`、`is_O_in_issuer`、`is_O_in_subject`、`is_ST_in_subject`、`max_duration`、`max_time_diff`、`number_of_domains_in_cert`、`number_of_flows`、`packet_loss`、`recv_sent_pkts_ratio`、`recv_sent_size_ratio`、`ssl_version`、`std_domain_name_length`、`std_time_diff`、`subject_only_CN`、`resumed`、`SNI_ssl_ratio`。

其中前五类 TLS/证书枚举字段使用训练工件内持久化的稳定词典编码。缺失日志字段采用上游实现的哨兵值（例如 `-1` 或 `0`），并在结果中标记为未观测；不以 NFStream 统计特征替代。

## 运行时协议

Python 运行时继续接受单行 JSON 并输出单行 JSON，避免破坏 TypeScript 调用边界。其操作定义为：

| 操作 | 输入 | 输出 |
| --- | --- | --- |
| `extract` | PCAP 路径或字节临时路径 | 上游连接元组、30 项原始特征、TLS/证书/DNS 元数据与可关联五元组。 |
| `train` | 平台持久化的上游特征行、标签、算法 | 序列化的分类器、词典、类别顺序、评估指标、训练/验证计数。 |
| `score` | 已存工件与上游特征行 | 每一连接元组五类概率、预测类别及基于模型特征的解释项。 |

## 平台数据与接口契约

`flowFeatures` 保留原有 NFStream JSON，并新增上游特征 JSON；`detectionFlows.featureJson` 同时保存上游特征和说明信息。独立 HTTP 接口固定为 `POST /api/v1/detect`，采用 `Authorization: Bearer <API_KEY>`、multipart 字段 `file` 与可选 `modelVersionId`，并在响应中返回任务统计、逐元组五元组、TLS/QUIC 元数据、五类概率、风险解释和 NFStream 字段。

## 风险评分

风险评分不再混入 KitNET 异常分。它等于 `1 - P(benign)`，并由最高类别概率确定预测类别。解释信息包括预测类别置信度、模型算法、上游选中特征的原始值与缺失字段状态。

## 可验证性

测试包含：上游特征字段顺序断言、五类概率归一化、随机森林/GBDT 模型往返推理、HTTP Bearer 鉴权、上传—训练—激活—检测—归档链路，以及 MariaDB/MinIO/Zeek Docker Compose 启动检查。

## 归属与可追溯性

实现中保留 `Abonnen/Malicious_TLS_Detection` 来源链接与核心参数注释；新增代码仅负责 Python 3 兼容、Zeek JSON 解析、平台持久化、五分类标签适配和 HTTP/UI 契约，不将原始算法替换为其他分类器或异常检测方法。

## 参考

1. Abonnen, [Malicious_TLS_Detection](https://github.com/Abonnen/Malicious_TLS_Detection)。
2. 上游 `feature_extract/evaluate_data.py`、`feature_extract/connetion_tuple.py`、`machine_learning/include/Dataset.py`、`machine_learning/random_forest/random_forest.py`、`machine_learning/lightGBM/gbdt.py`（已在本次重构基线中审阅）。
