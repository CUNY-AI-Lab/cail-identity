import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  isValidCandidateAuthority,
  isValidCandidatePackagePayload,
  packagePayloadIdentity,
  runtimeDigest,
  type CandidateSource,
  type PackagePayload,
} from "./check-release-authority.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const githubApiVersion = "2026-03-10";
const githubRequestTimeoutMs = 15_000;

type GitObject = {
  sha?: unknown;
  type?: unknown;
};

type GitRef = {
  object?: GitObject;
};

type GitTag = {
  object?: GitObject;
};

type Repository = {
  default_branch?: unknown;
};

export type ReleaseRefContext = {
  packageVersion: string;
  repository: string;
  refType: string | undefined;
  refName: string | undefined;
  sha: string | undefined;
  expectedRuntimeSha256: string;
  actualRuntimeSha256: string;
  expectedPackagePayload: PackagePayload;
  actualPackagePayload: PackagePayload;
};

export type GithubJson = (path: string) => Promise<unknown>;

function fail(message: string): never {
  throw new Error(`cail-identity release ref blocked: ${message}`);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    fail(`GitHub returned an invalid ${label} object.`);
  }
  return value as Record<string, unknown>;
}

function sha(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/iu.test(value)) {
    fail(`GitHub returned an invalid ${label} SHA.`);
  }
  return value.toLowerCase();
}

function digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/iu.test(value)) {
    fail(`the candidate authority has an invalid ${label} digest.`);
  }
  return value.toLowerCase();
}

function gitObject(value: unknown, label: string): GitObject {
  return object(value, label) as GitObject;
}

function gitRef(value: unknown, label: string): GitRef {
  return object(value, label) as GitRef;
}

function gitTag(value: unknown, label: string): GitTag {
  return object(value, label) as GitTag;
}

function repository(value: unknown): Repository {
  return object(value, "repository") as Repository;
}

function encodedRefPath(kind: "heads" | "tags", ref: string): string {
  return ref
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/")
    .replace(/^/, `/git/ref/${kind}/`);
}

async function resolveTagCommit(
  repositoryPath: string,
  initial: GitObject,
  getJson: GithubJson,
): Promise<string> {
  let current = initial;
  for (let depth = 0; depth < 4; depth += 1) {
    const currentSha = sha(current.sha, "tag");
    if (current.type === "commit") return currentSha;
    if (current.type !== "tag") {
      fail(
        `release tag resolves to unsupported Git object type ${String(current.type)}.`,
      );
    }
    const tag = gitTag(
      await getJson(`${repositoryPath}/git/tags/${currentSha}`),
      "annotated tag",
    );
    current = gitObject(tag.object, "annotated tag target");
  }
  fail("release tag has too many nested annotated tags.");
}

/**
 * Verifies the release event tag against GITHUB_SHA and the live default
 * branch. The API callback is injectable so unit tests remain offline.
 */
export async function verifyReleaseRef(
  context: ReleaseRefContext,
  getJson: GithubJson,
): Promise<void> {
  const expectedTag = `v${context.packageVersion}`;
  if (context.refType !== "tag") {
    fail(`release workflow requires a tag ref, received ${String(context.refType)}.`);
  }
  if (context.refName !== expectedTag) {
    fail(
      `release tag ${String(context.refName)} does not match package version ${context.packageVersion}.`,
    );
  }
  const expectedRuntimeSha256 = digest(
    context.expectedRuntimeSha256,
    "runtime",
  );
  const actualRuntimeSha256 = digest(
    context.actualRuntimeSha256,
    "runtime",
  );
  if (actualRuntimeSha256 !== expectedRuntimeSha256) {
    fail("the release runtime source differs from the candidate behavior authority.");
  }
  if (!isValidCandidatePackagePayload(context.expectedPackagePayload)) {
    fail("the candidate package payload authority is invalid.");
  }
  if (!isValidCandidatePackagePayload(context.actualPackagePayload)) {
    fail("the packed package payload differs from the candidate authority.");
  }
  const workflowSha = sha(context.sha, "GITHUB_SHA");
  if (!/^[^/]+\/[^/]+$/u.test(context.repository)) {
    fail("GITHUB_REPOSITORY is missing or malformed.");
  }

  const repositoryPath = `/repos/${context.repository}`;
  const repositoryResponse = repository(await getJson(repositoryPath));
  if (
    typeof repositoryResponse.default_branch !== "string" ||
    repositoryResponse.default_branch.length === 0
  ) {
    fail("GitHub did not return a default branch.");
  }
  const defaultBranch = repositoryResponse.default_branch;
  const branchRef = gitRef(
    await getJson(
      `${repositoryPath}${encodedRefPath("heads", defaultBranch)}`,
    ),
    "default-branch ref",
  );
  const branchSha = sha(branchRef.object?.sha, "default-branch head");
  if (branchRef.object?.type !== "commit") {
    fail("the live default-branch ref does not resolve directly to a commit.");
  }

  const tagRef = gitRef(
    await getJson(`${repositoryPath}${encodedRefPath("tags", expectedTag)}`),
    "release tag ref",
  );
  const tagSha = await resolveTagCommit(
    repositoryPath,
    gitObject(tagRef.object, "release tag target"),
    getJson,
  );
  if (workflowSha !== tagSha) {
    fail("GITHUB_SHA is not the commit named by the release tag.");
  }
  if (workflowSha !== branchSha) {
    fail("the release tag is not the live default-branch head.");
  }
}

async function githubJson(path: string, token: string): Promise<unknown> {
  const signal = AbortSignal.timeout(githubRequestTimeoutMs);
  let response: Response;
  try {
    response = await fetch(`https://api.github.com${path}`, {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": githubApiVersion,
      },
      signal,
    });
  } catch (error) {
    if (error instanceof Error && error.name === "TimeoutError") {
      fail(`GitHub API request timed out after 15 seconds for ${path}.`);
    }
    fail(`GitHub API request failed for ${path}.`);
  }
  if (!response.ok) {
    fail(`GitHub API ${response.status} ${response.statusText} for ${path}.`);
  }
  try {
    return await response.json();
  } catch {
    fail(`GitHub API returned an unreadable response for ${path}.`);
  }
}

async function main(): Promise<void> {
  const packageJson = JSON.parse(
    readFileSync(resolve(root, "package.json"), "utf8"),
  ) as { version?: unknown };
  if (typeof packageJson.version !== "string" || packageJson.version.length === 0) {
    fail("package.json has no release version.");
  }
  const candidateAuthority = JSON.parse(
    readFileSync(
      resolve(root, "evidence/package-release-authority-candidate-6.0.0.json"),
      "utf8",
    ),
  ) as unknown;
  if (!isValidCandidateAuthority(candidateAuthority)) {
    fail("candidate source authority is invalid.");
  }
  const source = (candidateAuthority as {
    source: CandidateSource;
    behavior_authority: { runtime_sha256: string };
    package_payload: PackagePayload;
  }).source;
  if (source.tag !== `v${packageJson.version}`) {
    fail("candidate source authority tag does not match package version.");
  }
  const authority = candidateAuthority as {
    behavior_authority: { runtime_sha256: string };
    package_payload: PackagePayload;
  };
  const token = process.env.GH_TOKEN;
  if (!token) fail("GH_TOKEN is required for the live GitHub ref check.");
  await verifyReleaseRef(
    {
      packageVersion: packageJson.version,
      repository: process.env.GITHUB_REPOSITORY ?? "",
      refType: process.env.GITHUB_REF_TYPE,
      refName: process.env.GITHUB_REF_NAME,
      sha: process.env.GITHUB_SHA,
      expectedRuntimeSha256: authority.behavior_authority.runtime_sha256,
      actualRuntimeSha256: runtimeDigest(),
      expectedPackagePayload: authority.package_payload,
      actualPackagePayload: packagePayloadIdentity(),
    },
    (path) => githubJson(path, token),
  );
}

const invoked = process.argv[1]
  ? resolve(process.argv[1])
  : undefined;
if (invoked === fileURLToPath(import.meta.url)) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
