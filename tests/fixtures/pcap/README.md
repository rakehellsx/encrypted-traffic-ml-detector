# 安全合成 PCAP 测试夹具

本目录中的流量包仅用于验证本项目的上传、流特征提取、多分类训练、模型加载、离线检测、HTTP 检测接口和 NFStream 历史持久化链路。所有地址均使用文档保留网段，文件不含恶意程序、攻击载荷、真实用户流量、凭据或可执行内容；它们**不能**用于证明真实 TLS 1.3/ECH 或恶意流量检测性能。

| 文件 | 用途 | SHA-256 |
|---|---|---|
| `synthetic-tls-handshakes.pcap` | TLS ClientHello 可见字段、TLS 版本、SNI、JA3、SPLT 解析回归 | `64b159117bfac2c302300ada6d4b3f9e4e58509fcf1c0d3d8d6ab239818f7d90` |
| `ui-benign.pcap` | 正常流量类别的上传与训练回归 | `06bd31e10256fda2ec332462ad6c83f1618124f14f35ff97388c0f4ae8c0305a` |
| `ui-c2-channel.pcap` | 命令控制类别的上传与训练回归 | `3db6f5c7cdfe9fd14d7458fffe9ee9b922137e76d44fe75d0bcee1fe01c28440` |
| `ui-data-exfiltration.pcap` | 数据外传类别的上传与训练回归 | `3ec03f4663a4356c7b6e782d6b9ccdb7216a53a3efaf11f9b3e6cdd8732a2a9e` |
| `ui-detection-target.pcap` | 已训练模型的离线与 HTTP 检测回归 | `7efbe887f43d20d3276d27eb99067a37aa60d3b4524ead263cb50c2b160705e5` |

可使用下列命令核验文件未被篡改：

```bash
sha256sum tests/fixtures/pcap/*.pcap
```

端到端回归可通过 `pnpm test:e2e` 执行。需要在公共工作区保留本轮验证生成的训练数据、模型、检测任务及审计记录时，使用：

```bash
KEEP_E2E_DATA=1 pnpm test:e2e
```
