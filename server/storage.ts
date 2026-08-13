import { CreateBucketCommand, GetObjectCommand, HeadBucketCommand, PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { ENV } from "./_core/env";

function normalizeKey(relKey: string) {
  return relKey.replace(/^\/+/, "");
}

function appendHashSuffix(relKey: string) {
  const hash = crypto.randomUUID().replace(/-/g, "").slice(0, 8);
  const lastDot = relKey.lastIndexOf(".");
  return lastDot === -1 ? `${relKey}_${hash}` : `${relKey.slice(0, lastDot)}_${hash}${relKey.slice(lastDot)}`;
}

function minioConfig() {
  const endpoint = process.env.S3_ENDPOINT;
  const region = process.env.S3_REGION ?? "us-east-1";
  const bucket = process.env.S3_BUCKET;
  const accessKeyId = process.env.S3_ACCESS_KEY;
  const secretAccessKey = process.env.S3_SECRET_KEY;
  if (!endpoint || !bucket || !accessKeyId || !secretAccessKey) return null;
  return {
    bucket,
    client: new S3Client({ endpoint, region, forcePathStyle: true, credentials: { accessKeyId, secretAccessKey } }),
  };
}

let bucketReady: Promise<void> | null = null;
async function ensureBucket() {
  const config = minioConfig();
  if (!config) return null;
  bucketReady ??= (async () => {
    try {
      await config.client.send(new HeadBucketCommand({ Bucket: config.bucket }));
    } catch {
      await config.client.send(new CreateBucketCommand({ Bucket: config.bucket }));
    }
  })();
  await bucketReady;
  return config;
}

function forgeConfig() {
  const forgeUrl = ENV.forgeApiUrl;
  const forgeKey = ENV.forgeApiKey;
  if (!forgeUrl || !forgeKey) throw new Error("Storage config missing: set S3_* for MinIO or BUILT_IN_FORGE_API_URL and BUILT_IN_FORGE_API_KEY");
  return { forgeUrl: forgeUrl.replace(/\/+$/, ""), forgeKey };
}

/** Stores original PCAP data in MinIO in self-hosted deployment, or Forge storage in dev. */
export async function storagePut(relKey: string, data: Buffer | Uint8Array | string, contentType = "application/octet-stream"): Promise<{ key: string; url: string }> {
  const key = appendHashSuffix(normalizeKey(relKey));
  const s3 = await ensureBucket();
  if (s3) {
    await s3.client.send(new PutObjectCommand({ Bucket: s3.bucket, Key: key, Body: data, ContentType: contentType }));
    return { key, url: `/api/storage/${encodeURIComponent(key)}` };
  }
  const { forgeUrl, forgeKey } = forgeConfig();
  const presignUrl = new URL("v1/storage/presign/put", `${forgeUrl}/`);
  presignUrl.searchParams.set("path", key);
  const presignResp = await fetch(presignUrl, { headers: { Authorization: `Bearer ${forgeKey}` } });
  if (!presignResp.ok) throw new Error(`Storage presign failed (${presignResp.status}): ${await presignResp.text()}`);
  const { url: target } = await presignResp.json() as { url: string };
  const uploadBody: BodyInit = typeof data === "string" ? data : Buffer.from(data) as unknown as BodyInit;
  const upload = await fetch(target, { method: "PUT", headers: { "Content-Type": contentType }, body: uploadBody });
  if (!upload.ok) throw new Error(`Storage upload failed (${upload.status})`);
  return { key, url: `/manus-storage/${key}` };
}

export async function storageGet(relKey: string) {
  const key = normalizeKey(relKey);
  return { key, url: `/api/storage/${encodeURIComponent(key)}` };
}

export async function storageGetSignedUrl(relKey: string) {
  const key = normalizeKey(relKey);
  const s3 = await ensureBucket();
  if (s3) return getSignedUrl(s3.client, new GetObjectCommand({ Bucket: s3.bucket, Key: key }), { expiresIn: 600 });
  const { forgeUrl, forgeKey } = forgeConfig();
  const url = new URL("v1/storage/presign/get", `${forgeUrl}/`);
  url.searchParams.set("path", key);
  const response = await fetch(url, { headers: { Authorization: `Bearer ${forgeKey}` } });
  if (!response.ok) throw new Error(`Storage signed URL failed (${response.status}): ${await response.text()}`);
  return (await response.json() as { url: string }).url;
}
