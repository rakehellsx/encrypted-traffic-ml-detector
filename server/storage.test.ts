import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getLocalStoredFilePath, localStoredFilePath, storagePut } from "./storage";

let root: string | undefined;
afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
  delete process.env.LOCAL_STORAGE_PATH;
  root = undefined;
});

describe("local production storage", () => {
  it("stores a file below the configured root and rejects traversal", async () => {
    root = await mkdtemp(join(tmpdir(), "trafficguard-storage-"));
    process.env.LOCAL_STORAGE_PATH = root;
    const stored = await storagePut("uploads/safe.pcap", Buffer.from("pcap-fixture"), "application/vnd.tcpdump.pcap");
    const path = await getLocalStoredFilePath(stored.key);
    expect(stored.url).toMatch(/^\/api\/storage\//);
    expect(path).toBeTruthy();
    expect(await readFile(path!, "utf8")).toBe("pcap-fixture");
    expect(() => localStoredFilePath("../../etc/passwd")).toThrow("非法的本地存储路径");
  });
});
