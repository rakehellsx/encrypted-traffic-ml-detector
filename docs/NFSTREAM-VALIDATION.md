# NFStream 公开 QUIC 样本验证

本次验证使用公开仓库 `knqyf263/ndff` 中的 `tests/pcap/quic.pcap`。该文件仅作为 NFStream 与现有无解密检测管道的互操作样本，不代表恶意流量或 ECH 性能结论。

```bash
python3 scripts/validate_nfstream_sample.py /path/to/quic.pcap
```

NFStream 在该样本上提取到一条 UDP/443 双向流：413 个包、254,874 字节、37,932 ms 会话时长，以及前 24 个 SPLT 方向、包长和包间隔序列。结果证明无解密场景仍可获得流统计与时序侧信道特征。

该样本没有 ECH 标注、恶意标签或资产上下文；因此不能用于证明 ECH 检测准确率。TLS 1.3/ECH 的生产验收仍应采用带来源、时间、资产及恶意行为标签的近期授权流量，并将 SNI 缺失作为缺失标记而非恶意标签。

## 来源

- https://github.com/knqyf263/ndff — QUIC PCAP 测试样本。
- https://www.nfstream.org/docs/api — NFStream API 文档。
