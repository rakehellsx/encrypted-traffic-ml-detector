# NFStream 公开 QUIC 样本验证

本次验证使用公开仓库 `knqyf263/ndff` 中的 `tests/pcap/quic.pcap`。该仓库以 GPLv3 发布；本项目不将该 PCAP 纳入部署工件，仅将其作为本地可复现的验证样本。该文件不代表恶意流量或 ECH 性能结论。

```bash
python3 scripts/validate_nfstream_sample.py /path/to/quic.pcap
```

NFStream 在该样本上提取到一条 UDP/443 双向流：413 个包、254,874 字节、37,932 ms 会话时长，以及前 24 个 SPLT 方向、包长和包间隔序列。结果证明无解密场景仍可获得流统计与时序侧信道特征。

该样本没有 ECH 标注、恶意标签或资产上下文；因此不能用于证明 ECH 检测准确率。TLS 1.3/ECH 的生产验收仍应采用带来源、时间、资产及恶意行为标签的近期授权流量，并将 SNI 缺失作为缺失标记而非恶意标签。

## 来源

- https://github.com/knqyf263/ndff — QUIC PCAP 测试样本。
- https://github.com/lbirchler/tls-decryption — 包含 `data/tls3/tls3.cryptohack.org.pcapng` 的公开 TLS 1.3 示例；仓库许可证为 MIT。
- https://www.nfstream.org/docs/api — NFStream API 文档。

## TLS 1.3 样本结果

在 `tls3.cryptohack.org.pcapng` 上，NFStream 识别出一条 TCP/443 TLS 流：29 个双向包、8,075 字节、188 ms 持续时间，并输出 24 个 SPLT 方向、包长和包间隔位置。该样本的 NFStream `application_name` 为 `TLS`。NFStream 的基础流对象在该运行配置中未输出 JA3 或 SNI 字段；现有解析器仍负责 TLS 版本、JA3 与 SNI 可见性详情。该边界说明 NFStream 应与协议解析器并联，而不应替代其 TLS 细节采集。

## 加密恶意流量候选

Stratosphere IPS 的 MCFP CTU-Malware-Capture-Botnet-42 公开提供 `botnet-capture-20110810-neris.pcap`，并说明该 PCAP 仅含 botnet 流量。页面同时提供标签说明：`From-Botnet` 是恶意流，`To-Botnet` 不应仅因目标地址而自动标为恶意；使用数据应引用 Malware Capture Facility Project。验证流程只允许下载和处理公开 PCAP 与标签文件，禁止下载、解压或执行同目录恶意二进制 ZIP。

MCFP 的详细双向流标签文件为 Argus 二进制格式，当前运行环境没有可靠的 `ra` 转换器，因此不应将其二进制片段直接喂入模型。另有 CTU-13 CSV 镜像可读出 botnet 与 normal 流特征，但镜像未声明许可证；它只能作为字段格式参考，不能替代原始数据的许可与引用要求。

## 安全合成 TLS 握手回归

`scripts/create_tls_handshake_pcap.py` 生成仅包含安全 ClientHello 元数据的 PCAP。它覆盖 TLS 1.3 与 TLS 1.2 记录版本、密码套件、supported groups、EC point formats、supported versions、SNI 和用于 JA3 的扩展序列；不包含恶意代码、攻击指令或真实用户内容。`scripts/inspect_synthetic_tls.ts` 验证解析器可输出每条流的五元组、TLS 版本、JA3、SNI 可见性和 SPLT。该样本只证明处理链路与字段解析，不代表真实流量分布、恶意检测准确率或 ECH 性能。
