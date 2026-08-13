import { spawn } from "node:child_process";
import { resolve } from "node:path";

/**
 * JSON bridge for the Abonnen/Malicious_TLS_Detection-compatible Python runtime.
 * The runtime owns the upstream feature schema, model training and probability inference.
 */
export function runAbonnenTlsEngine<T>(payload: unknown): Promise<T> {
  return new Promise((resolveResult, reject) => {
    const child = spawn("python3", [resolve(process.cwd(), "scripts/abonnen_tls_engine.py")], { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
    child.on("error", reject);
    child.on("close", (code: number | null) => {
      try {
        const output = JSON.parse(stdout.trim().split("\n").at(-1) || "{}");
        if (code !== 0 || output.error) reject(new Error(output.error || stderr || "Abonnen TLS 检测引擎运行失败"));
        else resolveResult(output as T);
      } catch {
        reject(new Error(stderr || "Abonnen TLS 检测引擎返回格式错误"));
      }
    });
    child.stdin.end(JSON.stringify(payload));
  });
}
