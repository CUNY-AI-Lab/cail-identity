import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  isValidArtifactIdentity,
  isValidCandidateAuthority,
  isValidHistoricalAuthority,
  isValidLiveVersions,
  isValidPublishedAuthority,
  isValidPublishedRegistryVersion,
  isValidPublishedSourceTag,
  runtimeDigest,
} from "../scripts/check-release-authority.js";
import {
  type GithubJson,
  verifyReleaseRef,
} from "../scripts/check-release-ref.js";

const root = resolve(import.meta.dirname, "..");
const historicalAuthority = JSON.parse(
  readFileSync(resolve(root, "evidence/package-release-authority.json"), "utf8"),
);
const publishedAuthority = JSON.parse(
  readFileSync(
    resolve(root, "evidence/package-release-authority-published.json"),
    "utf8",
  ),
);
const candidateAuthority = JSON.parse(
  readFileSync(
    resolve(root, "evidence/package-release-authority-candidate-5.1.1.json"),
    "utf8",
  ),
);
const packageJson = JSON.parse(
  readFileSync(resolve(root, "package.json"), "utf8"),
);
const releaseAuthorityScript = readFileSync(
  resolve(root, "scripts/check-release-authority.ts"),
  "utf8",
);
const publishWorkflow = readFileSync(
  resolve(root, ".github/workflows/publish.yml"),
  "utf8",
);
const readme = readFileSync(resolve(root, "README.md"), "utf8");
const ciWorkflow = readFileSync(
  resolve(root, ".github/workflows/ci.yml"),
  "utf8",
);

const currentHead = "a".repeat(40);
const oldHead = "b".repeat(40);

function releaseApi(
  tagSha: string,
  branchSha: string,
  treeSha = "c".repeat(40),
): GithubJson {
  const responses = new Map<string, unknown>([
    [
      "/repos/CUNY-AI-Lab/cail-identity",
      { default_branch: "main" },
    ],
    [
      "/repos/CUNY-AI-Lab/cail-identity/git/ref/heads/main",
      { object: { sha: branchSha, type: "commit" } },
    ],
    [
      "/repos/CUNY-AI-Lab/cail-identity/git/ref/tags/v5.1.0",
      { object: { sha: tagSha, type: "commit" } },
    ],
    [
      `/repos/CUNY-AI-Lab/cail-identity/git/commits/${tagSha}`,
      { tree: { sha: treeSha } },
    ],
  ]);
  return async (path) => {
    if (!responses.has(path)) throw new Error(`unexpected API path: ${path}`);
    return responses.get(path);
  };
}

const exactReleaseContext = {
  packageVersion: "5.1.0",
  repository: "CUNY-AI-Lab/cail-identity",
  refType: "tag",
  refName: "v5.1.0",
  sha: currentHead,
} as const;

describe("release version authority", () => {
  it("preserves the dated candidate observation separately from the published authority", () => {
    expect(isValidHistoricalAuthority(historicalAuthority)).toBe(true);
    expect(isValidPublishedAuthority(publishedAuthority)).toBe(true);
    expect(isValidCandidateAuthority(candidateAuthority)).toBe(true);
    expect(historicalAuthority.package.candidate_version).toBe("5.1.0");
    expect(candidateAuthority.package.candidate_version).toBe("5.1.1");
    expect(candidateAuthority.registry).not.toHaveProperty("workflow_receipt");
    expect(publishedAuthority.package).toEqual({
      name: "@cuny-ai-lab/cail-identity",
      version: "5.1.0",
    });
    expect(
      isValidPublishedAuthority({
        ...publishedAuthority,
        package: { ...publishedAuthority.package, version: "5.2.0" },
      }),
    ).toBe(false);
    expect(isValidHistoricalAuthority(historicalAuthority)).toBe(true);
  });

  it("derives the current runtime and validates source/tag and artifact identity", () => {
    expect(runtimeDigest()).toBe(
      "120e9cd9002b1fa6d9f9a61b07ffbabef8d17159bb36862849b1b51d8ca603a7",
    );
    expect(isValidPublishedSourceTag(publishedAuthority.release)).toBe(true);
    expect(
      isValidPublishedSourceTag({
        ...publishedAuthority.release,
        commit: "0".repeat(40),
      }),
    ).toBe(false);
    const artifact = {
      tarball: publishedAuthority.registry.tarball,
      artifact_sha1: publishedAuthority.registry.artifact_sha1,
      integrity: publishedAuthority.registry.integrity,
      artifact_bytes: publishedAuthority.registry.artifact_bytes,
      artifact_sha256: publishedAuthority.registry.artifact_sha256,
      artifact_git_tree_sha256:
        publishedAuthority.registry.artifact_git_tree_sha256,
    };
    expect(isValidArtifactIdentity(artifact)).toBe(true);
    expect(
      isValidArtifactIdentity({ ...artifact, artifact_sha256: "forged" }),
    ).toBe(false);
    expect(
      isValidArtifactIdentity({ ...artifact, tarball: `${artifact.tarball}x` }),
    ).toBe(false);
    expect(() => isValidArtifactIdentity(null)).not.toThrow();
  });

  it("requires the exact published registry version identity", () => {
    expect(
      isValidPublishedRegistryVersion({
        id: 1088911629,
        name: "5.1.0",
        created_at: "2026-08-01T17:01:12Z",
        updated_at: "2026-08-01T17:01:12Z",
      }),
    ).toBe(true);
    expect(
      isValidPublishedRegistryVersion({
        id: 1088911630,
        name: "5.1.0",
        created_at: "2026-08-01T17:01:12Z",
      }),
    ).toBe(false);
  });

  it("rejects occupied or malformed live registry snapshots", () => {
    const available = [
      {
        id: 1088911629,
        name: "5.1.0",
        created_at: "2026-08-01T17:01:12Z",
      },
    ];
    expect(isValidLiveVersions(available, "5.1.0")).toBe(false);
    expect(
      isValidLiveVersions(
        [
          {
            id: 1066308573,
            name: "5.0.0",
            created_at: "2026-07-25T17:27:05Z",
            updated_at: "2026-07-25T17:27:05Z",
          },
        ],
        "5.2.0",
      ),
    ).toBe(true);
    expect(isValidLiveVersions([], "5.2.0")).toBe(false);
    expect(isValidLiveVersions([{ name: "5.2.0" }], "5.2.0")).toBe(false);
    expect(isValidLiveVersions(new Array(1), "5.2.0")).toBe(false);
  });

  it("fails closed for forged, incomplete, and extended authorities", () => {
    const cases = [
      null,
      { ...publishedAuthority, package: { name: "forged", version: "5.1.0" } },
      {
        ...publishedAuthority,
        release: { ...publishedAuthority.release, tree: "0".repeat(40) },
      },
      {
        ...publishedAuthority,
        behavior_authority: {
          ...publishedAuthority.behavior_authority,
          runtime_sha256: "forged",
        },
      },
      {
        ...publishedAuthority,
        registry: { ...publishedAuthority.registry, integrity: "forged" },
      },
      {
        ...publishedAuthority,
        registry: { ...publishedAuthority.registry, extra: true },
      },
      (() => {
        const incomplete = { ...publishedAuthority };
        delete incomplete.release;
        return incomplete;
      })(),
    ];
    for (const candidate of cases) {
      expect(() => isValidPublishedAuthority(candidate)).not.toThrow();
      expect(isValidPublishedAuthority(candidate)).toBe(false);
    }
  });

  it("verifies the release tag, GITHUB_SHA, and live default-branch head", async () => {
    await expect(
      verifyReleaseRef(
        { ...exactReleaseContext, sha: oldHead },
        releaseApi(oldHead, currentHead),
      ),
    ).rejects.toThrow("live default-branch head");
    await expect(
      verifyReleaseRef(
        { ...exactReleaseContext, sha: oldHead },
        releaseApi(currentHead, currentHead),
      ),
    ).rejects.toThrow("GITHUB_SHA is not the commit named by the release tag");
    await expect(
      verifyReleaseRef(
        exactReleaseContext,
        releaseApi(oldHead, currentHead),
      ),
    ).rejects.toThrow("GITHUB_SHA is not the commit named by the release tag");
    await expect(
      verifyReleaseRef(exactReleaseContext, releaseApi(currentHead, currentHead)),
    ).resolves.toBeUndefined();
    await expect(
      verifyReleaseRef(
        {
          ...exactReleaseContext,
          expectedCommit: currentHead,
          expectedTree: "c".repeat(40),
        },
        releaseApi(currentHead, currentHead),
      ),
    ).resolves.toBeUndefined();
    await expect(
      verifyReleaseRef(
        {
          ...exactReleaseContext,
          expectedCommit: currentHead,
          expectedTree: "d".repeat(40),
        },
        releaseApi(currentHead, currentHead),
      ),
    ).rejects.toThrow("source tree differs");
  });

  it("keeps the live publish boundary explicit", () => {
    expect(packageJson.version).toBe("5.1.1");
    expect(packageJson.scripts.prepublishOnly).toContain(
      "bun run check:release-live",
    );
    expect(packageJson.scripts["check:release-live"]).toBe(
      "bun scripts/check-release-authority.ts --live",
    );
    expect(packageJson.scripts["check:release-ref"]).toBe(
      "bun scripts/check-release-ref.ts",
    );
    expect(releaseAuthorityScript).toContain("CAIL_REGISTRY_VERSIONS_FILE");
    expect(publishWorkflow).toContain("bun run check:release-ref");
    expect(publishWorkflow).toContain("GITHUB_SHA: ${{ github.sha }}");
    expect(publishWorkflow).toContain("gh api --paginate");
    expect(publishWorkflow).toContain("CAIL_REGISTRY_VERSIONS_FILE");
    expect(publishWorkflow).toContain("bun run check:release-live");
    expect(publishWorkflow).toContain(
      "NPM_CONFIG_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
    );
    expect(publishWorkflow).not.toContain("NODE_AUTH_TOKEN");
    expect(publishWorkflow).not.toContain("NPM_CONFIG_USERCONFIG");
    expect(publishWorkflow).not.toMatch(/>\s*\.npmrc/);
    expect(publishWorkflow).toContain(
      "NPM_CONFIG_REGISTRY: https://npm.pkg.github.com",
    );
    expect(ciWorkflow).toContain(
      "bun install --frozen-lockfile --ignore-scripts",
    );
  });

  it("documents the immutable README defect in the already-published artifact", () => {
    expect(readme).toContain("immutable 5.1.0 artifact");
    expect(readme).toContain("cannot be edited");
    expect(readme).toContain("follow-up version");
  });

  it("uses Bun's token authority without writing checkout credentials", () => {
    const npmrc = resolve(root, ".npmrc");
    expect(existsSync(npmrc)).toBe(false);
    const result = spawnSync(
      "bun",
      ["publish", "--dry-run", "--ignore-scripts"],
      {
        cwd: root,
        encoding: "utf8",
        env: {
          ...process.env,
          NPM_CONFIG_REGISTRY: "https://npm.pkg.github.com",
          NPM_CONFIG_TOKEN: "workflow-dry-run-placeholder",
        },
        timeout: 120_000,
      },
    );
    const output = (result.stdout ?? "") + (result.stderr ?? "");
    expect(result.status).toBe(0);
    expect(output).toContain(
      "+ @cuny-ai-lab/cail-identity@5.1.1 (dry-run)",
    );
    expect(existsSync(npmrc)).toBe(false);
  });
});
