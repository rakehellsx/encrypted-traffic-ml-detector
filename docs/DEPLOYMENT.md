# 部署与验收指南

## 部署架构

本项目使用 Docker Compose 部署三个长期运行服务：应用、MariaDB 11 和 MinIO。应用镜像从官方 Zeek 运行时派生，保证 Abonnen 检测引擎可以从 PCAP 生成 Zeek 连接、TLS、X.509 与 DNS 日志；官方文档说明 `zeek/zeek` 镜像为 Debian 基础并提供完整的 Zeek 安装。[1]

| 服务 | 职责 | 端口 | 持久化 |
| --- | --- | --- | --- |
| `app` | React/Express/tRPC、Abonnen ML、HTTP 检测接口 | 宿主机 `3001` | 模型工件保存至 MariaDB，PCAP 保存至 MinIO |
| `mariadb` | 训练数据、流特征、模型版本、检测任务、审计日志 | 内部网络 | `mariadb_data` |
| `minio` | 训练与检测 PCAP 的对象存储 | 内部网络 | `minio_data` |

所有服务均配置 `restart: unless-stopped`。公共工作区固定使用 `trafficguard_public_workspace`，因此平台页面不需要登录；独立检测接口仍使用 API Key 鉴权。

## 部署前准备

目标服务器应安装 Docker Engine 和 Docker Compose 插件，并将 TCP/3001 仅开放给预期访问范围。将已审阅的 `dev` 分支源码上传或拉取到 `/opt/trafficguard`。不要传输本地 `node_modules`、`.env`、构建缓存或任何私密令牌。

```bash
sudo mkdir -p /opt/trafficguard
sudo chown "$USER":"$USER" /opt/trafficguard
cd /opt/trafficguard
# 解压已审阅的源码包，或克隆并切换到 dev 分支。
```

`.env.server` 是部署机密，不得提交到 Git。以 `.env.server.example` 为模板并生成高熵随机值：

```bash
cd /opt/trafficguard
MARIADB_PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"
MARIADB_ROOT_PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"
MINIO_ROOT_PASSWORD="$(openssl rand -base64 36 | tr -d '\n')"
JWT_SECRET="$(openssl rand -base64 48 | tr -d '\n')"
cat > .env.server <<EOF
MARIADB_PASSWORD=${MARIADB_PASSWORD}
MARIADB_ROOT_PASSWORD=${MARIADB_ROOT_PASSWORD}
MINIO_ROOT_USER=trafficguard_minio
MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD}
JWT_SECRET=${JWT_SECRET}
EOF
chmod 600 .env.server
unset MARIADB_PASSWORD MARIADB_ROOT_PASSWORD MINIO_ROOT_PASSWORD JWT_SECRET
```

> 不要在源代码、文档、Issue、构建日志或 Git 提交中写入真实密码、API Key 或访问令牌。曾暴露于聊天记录的令牌应立即撤销并重新生成。

## 启动与数据库迁移

首次构建会拉取官方 Zeek 基础镜像，并安装 Python 的 scikit-learn、LightGBM 与 NFStream 依赖。运行下列命令启动服务；待数据库和对象存储健康后执行迁移。

```bash
cd /opt/trafficguard
docker compose --env-file .env.server -f docker-compose.server.yml up -d --build
docker compose --env-file .env.server -f docker-compose.server.yml ps
docker compose --env-file .env.server -f docker-compose.server.yml exec app pnpm db:push
```

迁移会添加 `flowFeatures.abonnenJson` 和 `flowFeatures.abonnenSource`，并保持旧版本模型为可查询的历史归档。新训练版本仅写入 `abonnen_random_forest` 或 `abonnen_gbdt`。

## 服务验收

以下命令验证应用进程、tRPC 和独立检测接口。tRPC 健康探针带有必需输入，因此应使用完整 URL。

```bash
curl -fsS "http://127.0.0.1:3001/api/trpc/system.health?input=%7B%22json%22%3A%7B%22timestamp%22%3A0%7D%7D"
curl -fsS http://127.0.0.1:3001/api/v1/detect/health
curl -I http://127.0.0.1:3001/
```

访问 `http://SERVER_IP:3001/` 后，应在公共工作区中看到“样本上传、数据管理、标注配置、模型训练、模型版本、流量检测、历史归档”。上传 PCAP 后，数据管理导出应同时保留 NFStream 并联字段和 Abonnen 上游特征；模型训练结果应包含 Accuracy、Precision、Recall、F1 与五类概率契约。

## 独立 HTTP 检测接口

在页面“流量检测”中创建 API Key。数据库仅保存 SHA-256 哈希，完整密钥仅会在创建时显示一次。接口为 `POST /api/v1/detect`，采用 `Authorization: Bearer`、multipart 字段 `file` 与可选 `modelVersionId`。

```bash
curl -fsS -X POST "http://SERVER_IP:3001/api/v1/detect" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -F "file=@tests/fixtures/pcap/sample-tls.pcap;type=application/vnd.tcpdump.pcap" \
  -F "modelVersionId=1"
```

响应包含任务级统计、逐流五元组、TLS/QUIC 元数据、五类概率、风险解释、NFStream 并联字段和上游特征值。风险评分定义为 `1 - P(benign)`，不再混合 KitNET 异常分。

## 本地开发与质量验证

```bash
pnpm install
sudo pip3 install -r requirements-ml.txt
pnpm check
pnpm test
pnpm build
pnpm test:e2e
```

`test:e2e` 需要可访问的 MariaDB、MinIO 和已启动的本地应用；可使用 `E2E_BASE_URL` 指向测试环境。脚本覆盖上传、五类模型训练、激活、检测、历史归档、NFStream/Abonnen 字段与 Bearer HTTP 接口，并在默认情况下清理测试记录。

## 日常运维

| 操作 | 命令 |
| --- | --- |
| 查看状态 | `docker compose --env-file .env.server -f docker-compose.server.yml ps` |
| 查看应用日志 | `docker compose --env-file .env.server -f docker-compose.server.yml logs -f app` |
| 更新至新 dev 提交 | `git pull --ff-only origin dev && docker compose --env-file .env.server -f docker-compose.server.yml up -d --build && docker compose --env-file .env.server -f docker-compose.server.yml exec app pnpm db:push` |
| 停止服务但保留数据 | `docker compose --env-file .env.server -f docker-compose.server.yml down` |

> 升级前应备份 MariaDB 与 MinIO 数据卷。不要使用 `docker compose down -v`，除非明确希望删除训练数据、模型版本、检测归档和 PCAP 对象。

## 参考

[1] [Zeek Project, *Installing Zeek — Docker Images*](https://docs.zeek.org/en/lts/install.html)。
