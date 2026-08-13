# Build the TypeScript/Vite application with the lockfile-pinned Node toolchain.
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm build

# The official Zeek image supplies the complete runtime required by
# Abonnen/Malicious_TLS_Detection feature extraction.
FROM zeek/zeek:lts AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    PORT=3001 \
    PATH="/usr/local/zeek/bin:/usr/local/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-pip python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Keep the official Zeek base intact while adding the Node runtime, application,
# generated production bundle, migration schema and Python feature engine.
COPY --from=build /usr/local /usr/local
COPY --from=build /app/package.json /app/pnpm-lock.yaml ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/drizzle ./drizzle
COPY --from=build /app/drizzle.config.ts ./drizzle.config.ts
COPY --from=build /app/scripts ./scripts
COPY --from=build /app/requirements-ml.txt ./requirements-ml.txt

RUN pip3 install --no-cache-dir -r requirements-ml.txt \
    && node --version \
    && python3 --version \
    && zeek --version

EXPOSE 3001
CMD ["node", "dist/index.js"]
