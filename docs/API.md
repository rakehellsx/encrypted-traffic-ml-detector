# HTTP 接口文档

## PCAP 检测

```http
POST /api/v1/detect
```

接口接收 `multipart/form-data`，并要求在请求头中携带已生成的 API Key。

| 字段 | 位置 | 必需 | 说明 |
| --- | --- | --- | --- |
| `x-api-key` | Header | 是 | 独立检测接口密钥。 |
| `pcap` | Form data | 是 | 离线 PCAP 文件。 |
| `modelId` | Form data | 否 | 指定模型版本 ID；省略时使用当前激活模型。 |

### cURL 示例

```bash
curl -X POST 'https://YOUR_DOMAIN/api/v1/detect' \
  -H 'x-api-key: YOUR_API_KEY' \
  -F 'pcap=@sample.pcap' \
  -F 'modelId=180001'
```

### 返回结构

成功时接口返回任务编号、整体摘要和逐流检测结果。逐流对象包含五元组、流统计、SPLT、TLS/QUIC 可见元数据、多分类概率、风险等级与解释原因。

```json
{
  "taskId": 240001,
  "summary": {
    "flowCount": 3,
    "classDistribution": { "data_exfiltration": 3 },
    "riskDistribution": { "critical": 3 },
    "encryptionMetadata": { "tlsFlows": 0, "quicFlows": 0 }
  },
  "flows": [
    {
      "network": {
        "fiveTuple": {
          "sourceIp": "10.30.5.3",
          "sourcePort": 50002,
          "destinationIp": "203.0.113.15",
          "destinationPort": 443,
          "transportProtocol": "TCP"
        }
      },
      "classification": {
        "predictedClass": "data_exfiltration",
        "confidence": 0.985,
        "probabilities": { "benign": 0.001, "c2_channel": 0.014, "data_exfiltration": 0.985 }
      },
      "risk": {
        "level": "critical",
        "score": 0.999,
        "reasons": ["特征偏离训练基线"]
      }
    }
  ]
}
```

请求失败时会返回相应 HTTP 状态码与错误信息。常见原因包括 API Key 缺失/失效、没有可用模型、PCAP 格式不支持或文件超过服务端限制。
