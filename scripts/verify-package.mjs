import { readFile } from "node:fs/promises";

const manifest = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

if (!manifest.repository?.url?.endsWith("/vega-plugin-richtext-bbcode.git")) {
  throw new Error("package repository must point to the independent BBCode plugin repository");
}
if (manifest.publishConfig?.access !== "public" || manifest.publishConfig?.provenance !== true) {
  throw new Error("public provenance publishing is required");
}
if (!manifest.vega?.capabilities?.includes("rich-text")) {
  throw new Error("rich-text capability metadata is required");
}
if (
  manifest.dependencies?.["@bbob/parser"] !== "4.4.1" ||
  manifest.dependencies?.["@bbob/html"] !== "4.4.1" ||
  manifest.dependencies?.dompurify !== "3.4.12"
) {
  throw new Error("reviewed parser, renderer, and sanitizer versions must be pinned");
}
if (manifest.peerDependencies?.["@haneoka/vega-plugin-richtext"] !== "^0.1.0") {
  throw new Error("the format-neutral rich-text service must be a peer");
}

process.stdout.write("BBCode rich-text plugin package boundary verified\n");
