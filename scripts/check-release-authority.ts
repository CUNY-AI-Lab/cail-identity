import { createHash } from "node:crypto";
import {
  readFileSync,
  readdirSync,
  statSync,
} from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const authorityPath = resolve(
  root,
  "evidence/package-release-authority.json",
);
const expectedRuntimeSha256 =
  "2300e88d443a6badb87dc34b73bcb8f41fc3e53f740938357d1e490fb06ea93a";

type Version = {
  id?: unknown;
  name?: unknown;
  created_at?: unknown;
};

type Authority = {
  schema_version?: unknown;
  package?: { name?: unknown; candidate_version?: unknown };
  behavior_authority?: {
    commit?: unknown;
    tree?: unknown;
    runtime_paths?: unknown;
    runtime_sha256?: unknown;
  };
  registry?: {
    url?: unknown;
    api?: unknown;
    observed_at?: unknown;
    published_versions?: unknown;
    candidate_state?: unknown;
  };
};

function filesBelow(path: string): string[] {
  return readdirSync(path, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => resolve(entry.parentPath, entry.name));
}

export function runtimeDigest(): string {
  const files = ["contract", "src"]
    .flatMap((path) => filesBelow(resolve(root, path)))
    .sort();
  const hash = createHash("sha256");
  for (const path of files) {
    const contents = readFileSync(path);
    hash.update(`${relative(root, path)}\0${contents.length}\0`);
    hash.update(contents);
  }
  return hash.digest("hex");
}

export function isValidAuthority(authority: Authority): boolean {
  const published = authority.registry?.published_versions;
  return (
    authority.schema_version === 1 &&
    authority.package?.name === "@cuny-ai-lab/cail-identity" &&
    authority.package?.candidate_version === "5.1.0" &&
    authority.behavior_authority?.commit ===
      "949839868f5bdac6ceb936fd83fe298aff3ad60c" &&
    authority.behavior_authority?.tree ===
      "7d008404aefa2b7ad981b5747f8522fd162fb356" &&
    JSON.stringify(authority.behavior_authority?.runtime_paths) ===
      JSON.stringify(["contract", "src"]) &&
    authority.behavior_authority?.runtime_sha256 ===
      expectedRuntimeSha256 &&
    authority.registry?.url === "https://npm.pkg.github.com" &&
    authority.registry?.api ===
      "https://api.github.com/orgs/CUNY-AI-Lab/packages/npm/cail-identity/versions" &&
    typeof authority.registry?.observed_at === "string" &&
    authority.registry.candidate_state === "not_published" &&
    Array.isArray(published) &&
    published.some(
      (entry) =>
        typeof entry === "object" &&
        entry !== null &&
        (entry as Record<string, unknown>).version === "5.0.0" &&
        (entry as Record<string, unknown>).package_version_id ===
          1066308573 &&
        (entry as Record<string, unknown>).published_at ===
          "2026-07-25T17:27:05Z",
    )
  );
}

export function isValidLiveVersions(versions: Version[]): boolean {
  return (
    versions.some(
      (version) =>
        version.id === 1066308573 &&
        version.name === "5.0.0" &&
        version.created_at === "2026-07-25T17:27:05Z",
    ) && !versions.some((version) => version.name === "5.1.0")
  );
}

function main(): void {
  const authority = JSON.parse(
    readFileSync(authorityPath, "utf8"),
  ) as Authority;
  const packageJson = JSON.parse(
    readFileSync(resolve(root, "package.json"), "utf8"),
  ) as { name?: unknown; version?: unknown };
  if (
    !isValidAuthority(authority) ||
    packageJson.name !== "@cuny-ai-lab/cail-identity" ||
    packageJson.version !== "5.1.0" ||
    runtimeDigest() !== expectedRuntimeSha256 ||
    statSync(authorityPath).size === 0
  ) {
    throw new Error(
      "cail-identity: local release authority is invalid",
    );
  }
  if (process.argv.includes("--live")) {
    const versionsPath = process.env.CAIL_REGISTRY_VERSIONS_FILE;
    if (!versionsPath) {
      throw new Error(
        "cail-identity: live registry preflight requires CAIL_REGISTRY_VERSIONS_FILE",
      );
    }
    const versions = JSON.parse(
      readFileSync(versionsPath, "utf8"),
    ) as Version[];
    if (!Array.isArray(versions) || !isValidLiveVersions(versions)) {
      throw new Error(
        "cail-identity: registry version authority changed or 5.1.0 already exists",
      );
    }
  }
}

const invoked = process.argv[1]
  ? resolve(process.argv[1])
  : undefined;
if (invoked === fileURLToPath(import.meta.url)) main();
