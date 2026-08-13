# 部署指南

## 1. 运行要求

建议使用 Node.js 22、pnpm 10、MySQL/TiDB 兼容数据库以及可供服务端访问的对象存储。生产环境应配置反向代理或受控网关，限制公共控制台的来源网络和上传文件大小。

| 配置项 | 作用 | 是否必需 |
| --- | --- | --- |
| `DATABASE_URL` | 数据库连接字符串。 | 是 |
| `JWT_SECRET` | 框架会话签名配置。 | 是 |
| 对象存储凭据 | 存储 PCAP 与分析工件。 | 是 |
| `BUILT_IN_FORGE_API_*` | Manus 托管环境的存储与平台服务配置。 | 托管环境中由平台注入 |

> 不要在源代码、文档、Issue、构建日志或 Git 提交中写入任何真实密钥。对于曾暴露在聊天记录或终端的令牌，应立即在相应平台撤销并重新生成。

## 2. 本地开发

```bash
pnpm install
pnpm dev
```

服务启动后，前端由 Vite 提供热更新，Express 同时暴露 tRPC 与 `/api/v1/detect`。使用本地环境变量文件时，请确保该文件被 `.gitignore` 忽略。

## 3. 数据库迁移

修改 `drizzle/schema.ts` 后，先生成迁移，再审查 SQL，最后在目标数据库中应用迁移。

```bash
pnpm drizzle-kit generate
```

生产环境应在变更窗口内执行迁移，并先备份 `datasets`、`flowFeatures`、`modelVersions`、`detectionTasks`、`detectionFlows` 和 `operationLogs`。本项目的数据模型包含历史归档和审计日志；清理策略应按组织的保留规则执行。

## 4. 质量验证与构建

```bash
pnpm test
pnpm test:e2e
pnpm check
pnpm build
```

`test:e2e` 会以可控的最小 PCAP 验证样本上传、特征解析、多分类训练、模型激活、HTTP 检测、审计日志、历史分页与导出，并在完成后清理测试记录。

## 5. Manus 托管发布

本项目在 Manus WebDev 中配置自动发布。保存检查点后，平台会构建并更新已配置域名。当前部署地址为：

```text
https://enctrf-detec-8nt4qn6a.manus.space/
```

发布后应至少检查样本上传、模型训练、流量检测、历史归档与 `/api/v1/detect` 的 API Key 鉴权。若控制台继续采用无登录模式，请限制域名访问范围；不要将其直接暴露给不受信任的互联网用户。
