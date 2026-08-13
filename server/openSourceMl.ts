import { spawn } from "node:child_process";
import { resolve } from "node:path";

export function runOpenSourceMl<T>(payload: unknown): Promise<T> {
  return new Promise((resolveResult, reject) => {
    const child = spawn("python3", [resolve(process.cwd(), "scripts/open_source_ml.py")], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = ""; let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); }); child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on("error", reject); child.on("close", (code: number | null) => { try { const output = JSON.parse(stdout.trim().split("\n").at(-1) || "{}"); if (code !== 0 || output.error) reject(new Error(output.error || stderr || "开源模型运行失败")); else resolveResult(output as T); } catch { reject(new Error(stderr || "开源模型返回格式错误")); } });
    child.stdin.end(JSON.stringify(payload));
  });
}
