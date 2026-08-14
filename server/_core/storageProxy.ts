import type { Express } from "express";
import { getLocalStoredFilePath, storageGetSignedUrl } from "../storage";

/** Serves local protected files or redirects object-store files without exposing credentials. */
export function registerStorageProxy(app: Express) {
  app.get(["/manus-storage/*", "/api/storage/*"], async (req, res) => {
    const key = (req.params as Record<string, string>)[0];
    if (!key) {
      res.status(400).send("Missing storage key");
      return;
    }
    try {
      const decodedKey = decodeURIComponent(key);
      const localPath = await getLocalStoredFilePath(decodedKey);
      res.set("Cache-Control", "no-store");
      if (localPath) {
        res.sendFile(localPath, error => {
          if (error && !res.headersSent) res.status(404).send("Stored file not found");
        });
        return;
      }
      res.redirect(307, await storageGetSignedUrl(decodedKey));
    } catch (error) {
      console.error("[StorageProxy] failed:", error);
      res.status(404).send("Storage backend error");
    }
  });
}
