import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const historicalAuthorityPath = resolve(
  root,
  "evidence/package-release-authority.json",
);
const publishedAuthorityPath = resolve(
  root,
  "evidence/package-release-authority-published.json",
);
const candidateAuthorityPath = resolve(
  root,
  "evidence/package-release-authority-candidate-5.2.0.json",
);

const packageName = "@cuny-ai-lab/cail-identity";
const historicalCandidateVersion = "5.1.0";
const publishedVersion = "5.1.0";
const candidateVersion = "5.2.0";
const historicalRuntimeSha256 =
  "2300e88d443a6badb87dc34b73bcb8f41fc3e53f740938357d1e490fb06ea93a";
const publishedRuntimeSha256 =
  "2300e88d443a6badb87dc34b73bcb8f41fc3e53f740938357d1e490fb06ea93a";
const historicalSource = {
  tag: "v5.1.0",
  commit: "15f3c6b92c79ab13a9d84df1061d72fabe4ad5e9",
} as const;
const publishedSource = {
  tag: "v5.1.0",
  commit: "15f3c6b92c79ab13a9d84df1061d72fabe4ad5e9",
  tree: "12ae8a872fa713b04ed3adf8add5dd9779c8c6b4",
} as const;
const publishedRegistryVersion = {
  id: 1088911629,
  name: publishedVersion,
  created_at: "2026-08-01T17:01:12Z",
} as const;
const publishedArtifact = {
  tarball:
    "https://npm.pkg.github.com/download/@cuny-ai-lab/cail-identity/5.1.0/27675a38c797795d11c3e99b8f7d2e519731faf2",
  artifact_sha1: "27675a38c797795d11c3e99b8f7d2e519731faf2",
  integrity:
    "sha512-L4XnjVlefEctstO7OKCPnQV0yv/WQyIuowx6aBe1Tq603iANuDCTp16n5llwmVEOC2tRh1CDnRQuD06kJZASFQ==",
  artifact_bytes: 37721,
  artifact_sha256:
    "763563d717ad6816cf300eea5dda3c059e87794ee2bc4f731701d5be32200735",
  artifact_git_tree_sha256:
    "cf517d3873386014325b305f422d9c223cd73f03dd83bbe7f8525a281cad7420",
} as const;
const candidateBehavior = {
  commit: "a407b932112c11a77cf3a7e26e7345b1b566ac17",
  tree: "88e69c84bab95dc14abeab6196cae6fc3432812d",
  runtimeSha256:
    "932dafab753fbae38c8cc37b76592835d880a764b98d51c602b9a0adc6323830",
} as const;
const candidateSource = {
  tag: "v5.2.0",
  commit: "a407b932112c11a77cf3a7e26e7345b1b566ac17",
  tree: "88e69c84bab95dc14abeab6196cae6fc3432812d",
} as const;
const candidatePackagePayload = {
  tarball_sha256:
    "7dcfb24a6bfcb81f7bc65eccee241842a7a47b447ffe4b82381969f72fa79e7a",
  tarball_bytes: 42065,
  files: [
    "LICENSE",
    "README.md",
    "contract/identity-jwt-claims-v1.json",
    "contract/identity-keyring-v1.json",
    "contract/principal-v1.json",
    "contract/subject-derivation-v2.json",
    "contract/subject-derivation-v2.lua",
    "dist/index.d.ts",
    "dist/index.d.ts.map",
    "dist/index.js",
    "dist/testing.d.ts",
    "dist/testing.d.ts.map",
    "dist/testing.js",
    "package.json",
    "src/index.ts",
    "src/testing.ts",
  ],
} as const;

type UnknownRecord = Record<string, unknown>;

export type CandidateSource = {
  tag: string;
  commit: string;
  tree: string;
};

export type PackagePayload = {
  tarball_sha256: string;
  tarball_bytes: number;
  files: readonly string[];
};

type RegistryVersion = {
  id?: unknown;
  name?: unknown;
  created_at?: unknown;
};

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(
  value: unknown,
  expected: readonly string[],
): value is UnknownRecord {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value);
  return (
    actual.length === expected.length &&
    expected.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function hasFields(
  value: unknown,
  expected: readonly string[],
): value is UnknownRecord {
  return (
    isRecord(value) &&
    expected.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function runtimePaths(value: unknown): boolean {
  return (
    Array.isArray(value) &&
    value.length === 2 &&
    value[0] === "contract" &&
    value[1] === "src"
  );
}

function validHistoricalWorkflowReceipt(value: unknown): boolean {
  if (
    !hasExactKeys(value, [
      "source",
      "claim",
      "observed_at",
      "workflow_run_id",
      "workflow_run_url",
      "workflow_job_id",
      "workflow_job_url",
      "run_status",
      "run_conclusion",
      "release_id",
      "release_url",
      "tag",
      "commit",
      "published_at",
    ])
  ) {
    return false;
  }
  return (
    value.source === "github-actions-publish-workflow" &&
    value.claim === "workflow_completed_successfully_registry_unverified" &&
    value.observed_at === "2026-08-01T18:40:58Z" &&
    value.workflow_run_id === 30709375309 &&
    value.workflow_run_url ===
      "https://github.com/CUNY-AI-Lab/cail-identity/actions/runs/30709375309" &&
    value.workflow_job_id === 91394005405 &&
    value.workflow_job_url ===
      "https://github.com/CUNY-AI-Lab/cail-identity/actions/runs/30709375309/job/91394005405" &&
    value.run_status === "completed" &&
    value.run_conclusion === "success" &&
    value.release_id === 363577354 &&
    value.release_url ===
      "https://github.com/CUNY-AI-Lab/cail-identity/releases/tag/v5.1.0" &&
    value.tag === historicalSource.tag &&
    value.commit === historicalSource.commit &&
    value.published_at === "2026-08-01T17:00:16Z"
  );
}

function validHistoricalVersion(value: unknown, expected: {
  version: string;
  package_version_id: number;
  published_at: string;
}): boolean {
  return (
    hasExactKeys(value, ["version", "package_version_id", "published_at"]) &&
    value.version === expected.version &&
    value.package_version_id === expected.package_version_id &&
    value.published_at === expected.published_at
  );
}

/** Preserved audit record only; its candidate fields are never publish gates. */
export function isValidHistoricalAuthority(value: unknown): boolean {
  if (
    !hasExactKeys(value, [
      "schema_version",
      "package",
      "behavior_authority",
      "registry",
    ]) ||
    value.schema_version !== 1 ||
    !hasExactKeys(value.package, ["name", "candidate_version"]) ||
    value.package.name !== packageName ||
    value.package.candidate_version !== historicalCandidateVersion ||
    !hasExactKeys(value.behavior_authority, [
      "commit",
      "tree",
      "runtime_paths",
      "runtime_sha256",
    ]) ||
    value.behavior_authority.commit !==
      "949839868f5bdac6ceb936fd83fe298aff3ad60c" ||
    value.behavior_authority.tree !==
      "7d008404aefa2b7ad981b5747f8522fd162fb356" ||
    !runtimePaths(value.behavior_authority.runtime_paths) ||
    value.behavior_authority.runtime_sha256 !== historicalRuntimeSha256 ||
    !hasExactKeys(value.registry, [
      "url",
      "api",
      "observed_at",
      "published_versions",
      "candidate_state",
      "candidate_state_scope",
      "workflow_receipt",
    ]) ||
    value.registry.url !== "https://npm.pkg.github.com" ||
    value.registry.api !==
      "https://api.github.com/orgs/CUNY-AI-Lab/packages/npm/cail-identity/versions" ||
    value.registry.observed_at !== "2026-08-01T16:50:26Z" ||
    value.registry.candidate_state !== "not_published" ||
    value.registry.candidate_state_scope !== "last_registry_observation" ||
    !validHistoricalWorkflowReceipt(value.registry.workflow_receipt) ||
    !Array.isArray(value.registry.published_versions) ||
    value.registry.published_versions.length !== 6
  ) {
    return false;
  }
  const expectedVersions = [
    ["5.0.0", 1066308573, "2026-07-25T17:27:05Z"],
    ["4.4.0", 1046174164, "2026-07-19T23:30:37Z"],
    ["4.3.0", 1046156313, "2026-07-19T23:09:25Z"],
    ["4.2.0", 1046114943, "2026-07-19T22:33:36Z"],
    ["4.1.0", 1046058154, "2026-07-19T21:51:19Z"],
    ["4.0.0", 1045860997, "2026-07-19T19:27:43Z"],
  ] as const;
  const versions = (value.registry as UnknownRecord).published_versions;
  if (!Array.isArray(versions)) return false;
  return expectedVersions.every(([version, id, publishedAt], index) =>
    validHistoricalVersion(
      versions[index],
      {
        version,
        package_version_id: id,
        published_at: publishedAt,
      },
    ),
  );
}

/** Candidate authority has source identity but no publication workflow receipt. */
export function isValidCandidateAuthority(value: unknown): boolean {
  const expectedVersions = [
    ["5.1.0", 1088911629, "2026-08-01T17:01:12Z"],
    ["5.0.0", 1066308573, "2026-07-25T17:27:05Z"],
    ["4.4.0", 1046174164, "2026-07-19T23:30:37Z"],
    ["4.3.0", 1046156313, "2026-07-19T23:09:25Z"],
    ["4.2.0", 1046114943, "2026-07-19T22:33:36Z"],
    ["4.1.0", 1046058154, "2026-07-19T21:51:19Z"],
    ["4.0.0", 1045860997, "2026-07-19T19:27:43Z"],
  ] as const;
  if (
    !hasExactKeys(value, [
      "schema_version",
      "package",
      "behavior_authority",
      "source",
      "package_payload",
      "registry",
    ]) ||
    value.schema_version !== 1 ||
    !hasExactKeys(value.package, ["name", "candidate_version"]) ||
    value.package.name !== packageName ||
    value.package.candidate_version !== candidateVersion ||
    !hasExactKeys(value.behavior_authority, [
      "commit",
      "tree",
      "runtime_paths",
      "runtime_sha256",
    ]) ||
    value.behavior_authority.commit !== candidateBehavior.commit ||
    value.behavior_authority.tree !== candidateBehavior.tree ||
    !runtimePaths(value.behavior_authority.runtime_paths) ||
    value.behavior_authority.runtime_sha256 !== candidateBehavior.runtimeSha256 ||
    !isValidCandidateSource(value.source) ||
    !isValidCandidatePackagePayload(value.package_payload) ||
    !hasExactKeys(value.registry, [
      "url",
      "api",
      "observed_at",
      "published_versions",
      "candidate_state",
      "candidate_state_scope",
    ]) ||
    value.registry.url !== "https://npm.pkg.github.com" ||
    value.registry.api !==
      "https://api.github.com/orgs/CUNY-AI-Lab/packages/npm/cail-identity/versions" ||
    value.registry.observed_at !== "2026-08-07T14:25:33Z" ||
    value.registry.candidate_state !== "not_published" ||
    value.registry.candidate_state_scope !== "last_registry_observation" ||
    !Array.isArray(value.registry.published_versions) ||
    value.registry.published_versions.length !== expectedVersions.length
  ) {
    return false;
  }
  const versions = value.registry.published_versions;
  return expectedVersions.every(([version, id, publishedAt], index) =>
    validHistoricalVersion(versions[index], {
      version,
      package_version_id: id,
      published_at: publishedAt,
    }),
  );
}

export function isValidCandidateSource(
  value: unknown,
): value is CandidateSource {
  return (
    hasExactKeys(value, ["tag", "commit", "tree"]) &&
    value.tag === candidateSource.tag &&
    value.commit === candidateSource.commit &&
    value.tree === candidateSource.tree
  );
}

function validPackagePayloadShape(value: unknown): value is PackagePayload {
  if (
    !hasExactKeys(value, ["tarball_sha256", "tarball_bytes", "files"]) ||
    typeof value.tarball_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/u.test(value.tarball_sha256) ||
    typeof value.tarball_bytes !== "number" ||
    !Number.isSafeInteger(value.tarball_bytes) ||
    value.tarball_bytes <= 0 ||
    !Array.isArray(value.files) ||
    value.files.length === 0
  ) {
    return false;
  }
  const files = value.files;
  for (let index = 0; index < files.length; index += 1) {
    if (
      !Object.prototype.hasOwnProperty.call(files, index) ||
      typeof files[index] !== "string" ||
      files[index].length === 0 ||
      (index > 0 && files[index - 1] >= files[index])
    ) {
      return false;
    }
  }
  return true;
}

export function isValidCandidatePackagePayload(
  value: unknown,
): value is PackagePayload {
  return (
    validPackagePayloadShape(value) &&
    value.tarball_sha256 === candidatePackagePayload.tarball_sha256 &&
    value.tarball_bytes === candidatePackagePayload.tarball_bytes &&
    value.files.length === candidatePackagePayload.files.length &&
    value.files.every(
      (file, index) => file === candidatePackagePayload.files[index],
    )
  );
}

/** Packs the exact published file allowlist without running package scripts. */
export function packagePayloadIdentity(): PackagePayload {
  const temporaryDirectory = mkdtempSync(join(tmpdir(), "cail-identity-pack-"));
  const archivePath = join(temporaryDirectory, "package.tgz");
  try {
    const packed = spawnSync(
      "bun",
      ["pm", "pack", "--ignore-scripts", "--filename", archivePath, "--quiet"],
      { cwd: root, encoding: "utf8" },
    );
    if (packed.status !== 0 || !existsSync(archivePath)) {
      throw new Error("cail-identity: unable to pack the candidate package");
    }
    const listing = spawnSync(
      "tar",
      ["-tzf", archivePath],
      { encoding: "utf8" },
    );
    if (listing.status !== 0 || typeof listing.stdout !== "string") {
      throw new Error("cail-identity: unable to inspect the candidate package");
    }
    const files = listing.stdout
      .split(/\r?\n/u)
      .filter((entry) => entry.length > 0)
      .map((entry) => {
        if (!entry.startsWith("package/") || entry.endsWith("/")) {
          throw new Error("cail-identity: package archive contains an invalid path");
        }
        return entry.slice("package/".length);
      })
      .sort();
    const archive = readFileSync(archivePath);
    return {
      tarball_sha256: createHash("sha256").update(archive).digest("hex"),
      tarball_bytes: statSync(archivePath).size,
      files,
    };
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

export function isValidPublishedSourceTag(value: unknown): boolean {
  return (
    hasFields(value, ["tag", "commit", "tree"]) &&
    value.tag === publishedSource.tag &&
    value.commit === publishedSource.commit &&
    value.tree === publishedSource.tree
  );
}

export function isValidArtifactIdentity(value: unknown): boolean {
  if (
    !hasExactKeys(value, [
      "tarball",
      "artifact_sha1",
      "integrity",
      "artifact_bytes",
      "artifact_sha256",
      "artifact_git_tree_sha256",
    ])
  ) {
    return false;
  }
  if (typeof value.tarball !== "string") return false;
  const tarballHash = value.tarball.split("/").at(-1);
  return (
    value.tarball === publishedArtifact.tarball &&
    value.artifact_sha1 === publishedArtifact.artifact_sha1 &&
    tarballHash === value.artifact_sha1 &&
    value.integrity === publishedArtifact.integrity &&
    value.artifact_bytes === publishedArtifact.artifact_bytes &&
    value.artifact_sha256 === publishedArtifact.artifact_sha256 &&
    value.artifact_git_tree_sha256 === publishedArtifact.artifact_git_tree_sha256
  );
}

export function isValidPublishedRegistryVersion(
  value: unknown,
): boolean {
  return (
    hasFields(value, ["id", "name", "created_at"]) &&
    value.id === publishedRegistryVersion.id &&
    value.name === publishedRegistryVersion.name &&
    value.created_at === publishedRegistryVersion.created_at
  );
}

export function isValidPublishedAuthority(value: unknown): boolean {
  if (
    !hasExactKeys(value, [
      "schema_version",
      "package",
      "behavior_authority",
      "release",
      "registry",
    ]) ||
    value.schema_version !== 1 ||
    !hasExactKeys(value.package, ["name", "version"]) ||
    value.package.name !== packageName ||
    value.package.version !== publishedVersion ||
    !hasExactKeys(value.behavior_authority, [
      "commit",
      "tree",
      "runtime_paths",
      "runtime_sha256",
    ]) ||
    value.behavior_authority.commit !==
      "949839868f5bdac6ceb936fd83fe298aff3ad60c" ||
    value.behavior_authority.tree !==
      "7d008404aefa2b7ad981b5747f8522fd162fb356" ||
    !runtimePaths(value.behavior_authority.runtime_paths) ||
    value.behavior_authority.runtime_sha256 !== publishedRuntimeSha256 ||
    !hasExactKeys(value.release, [
      "tag",
      "commit",
      "tree",
      "release_id",
      "release_url",
      "published_at",
      "workflow_run_id",
      "workflow_run_url",
      "workflow_job_id",
      "workflow_job_url",
      "run_status",
      "run_conclusion",
    ]) ||
    !isValidPublishedSourceTag({
      tag: value.release.tag,
      commit: value.release.commit,
      tree: value.release.tree,
    }) ||
    value.release.release_id !== 363577354 ||
    value.release.release_url !==
      "https://github.com/CUNY-AI-Lab/cail-identity/releases/tag/v5.1.0" ||
    value.release.published_at !== "2026-08-01T17:00:16Z" ||
    value.release.workflow_run_id !== 30709375309 ||
    value.release.workflow_run_url !==
      "https://github.com/CUNY-AI-Lab/cail-identity/actions/runs/30709375309" ||
    value.release.workflow_job_id !== 91394005405 ||
    value.release.workflow_job_url !==
      "https://github.com/CUNY-AI-Lab/cail-identity/actions/runs/30709375309/job/91394005405" ||
    value.release.run_status !== "completed" ||
    value.release.run_conclusion !== "success" ||
    !hasExactKeys(value.registry, [
      "url",
      "api",
      "package_id",
      "package_version_id",
      "version",
      "state",
      "created_at",
      "observed_at",
      "tarball",
      "artifact_sha1",
      "integrity",
      "artifact_bytes",
      "artifact_sha256",
      "artifact_git_tree_sha256",
    ]) ||
    value.registry.url !== "https://npm.pkg.github.com" ||
    value.registry.api !==
      "https://api.github.com/orgs/CUNY-AI-Lab/packages/npm/cail-identity/versions" ||
    value.registry.package_id !== 13479480 ||
    !isValidPublishedRegistryVersion({
      id: value.registry.package_version_id,
      name: value.registry.version,
      created_at: value.registry.created_at,
    }) ||
    value.registry.state !== "published" ||
    value.registry.observed_at !== "2026-08-06T20:45:16Z" ||
    !isValidArtifactIdentity({
      tarball: value.registry.tarball,
      artifact_sha1: value.registry.artifact_sha1,
      integrity: value.registry.integrity,
      artifact_bytes: value.registry.artifact_bytes,
      artifact_sha256: value.registry.artifact_sha256,
      artifact_git_tree_sha256: value.registry.artifact_git_tree_sha256,
    })
  ) {
    return false;
  }
  return true;
}

export function isValidAuthority(value: unknown): boolean {
  return isValidPublishedAuthority(value);
}

function validRegistryVersion(value: unknown): value is RegistryVersion {
  return (
    hasFields(value, ["id", "name", "created_at"]) &&
    typeof value.id === "number" &&
    Number.isSafeInteger(value.id) &&
    value.id > 0 &&
    typeof value.name === "string" &&
    value.name.length > 0 &&
    typeof value.created_at === "string" &&
    value.created_at.length > 0
  );
}

/** Returns true only for a complete registry response with no occupied version. */
export function isValidLiveVersions(
  versions: unknown,
  candidateVersion = publishedVersion,
): versions is RegistryVersion[] {
  if (
    typeof candidateVersion !== "string" ||
    candidateVersion.length === 0 ||
    !Array.isArray(versions) ||
    versions.length === 0
  ) {
    return false;
  }
  for (let index = 0; index < versions.length; index += 1) {
    if (
      !Object.prototype.hasOwnProperty.call(versions, index) ||
      !validRegistryVersion(versions[index])
    ) {
      return false;
    }
  }
  return !versions.some((version) => version.name === candidateVersion);
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

function filesBelow(path: string): string[] {
  return readdirSync(path, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => resolve(entry.parentPath, entry.name));
}

function main(): void {
  const historicalAuthority = JSON.parse(
    readFileSync(historicalAuthorityPath, "utf8"),
  ) as unknown;
  const publishedAuthority = JSON.parse(
    readFileSync(publishedAuthorityPath, "utf8"),
  ) as unknown;
  const candidateAuthority = JSON.parse(
    readFileSync(candidateAuthorityPath, "utf8"),
  ) as unknown;
  const packageJson = JSON.parse(
    readFileSync(resolve(root, "package.json"), "utf8"),
  ) as { name?: unknown; version?: unknown };
  if (
    !isValidHistoricalAuthority(historicalAuthority) ||
    !isValidPublishedAuthority(publishedAuthority) ||
    !isValidCandidateAuthority(candidateAuthority) ||
    packageJson.name !== packageName ||
    packageJson.version !== candidateVersion ||
    runtimeDigest() !== candidateBehavior.runtimeSha256 ||
    !isValidCandidatePackagePayload(packagePayloadIdentity())
  ) {
    throw new Error("cail-identity: local release authority is invalid");
  }
  if (process.argv.includes("--live")) {
    const versionsPath = process.env.CAIL_REGISTRY_VERSIONS_FILE;
    if (!versionsPath) {
      throw new Error(
        "cail-identity: live registry authority requires CAIL_REGISTRY_VERSIONS_FILE",
      );
    }
    const versions = JSON.parse(
      readFileSync(versionsPath, "utf8"),
    ) as unknown;
    if (!isValidLiveVersions(versions, packageJson.version)) {
      throw new Error(
        `cail-identity: registry version ${packageJson.version} is occupied or the live snapshot is invalid`,
      );
    }
  }
}

const invoked = process.argv[1]
  ? resolve(process.argv[1])
  : undefined;
if (invoked === fileURLToPath(import.meta.url)) main();
