import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  isValidArtifactIdentity,
  isValidCandidateAuthority,
  isValidCandidatePackagePayload,
  isValidCandidateSource,
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
const publishedAuthorityText = readFileSync(
  resolve(root, "evidence/package-release-authority-published.json"),
  "utf8",
);
const candidateAuthority = JSON.parse(
  readFileSync(
    resolve(root, "evidence/package-release-authority-candidate-5.2.0.json"),
    "utf8",
  ),
);
const burnedCandidateAuthority = JSON.parse(
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
const releaseRefScript = readFileSync(
  resolve(root, "scripts/check-release-ref.ts"),
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

const reviewedBehaviorCommit = candidateAuthority.source.commit;
const reviewedBehaviorTree = candidateAuthority.source.tree;
const releaseHead = "a".repeat(40);
const oldHead = "b".repeat(40);
const runtimeSha256 = candidateAuthority.behavior_authority.runtime_sha256;
const packagePayload = candidateAuthority.package_payload;

function releaseApi(
  tagSha: string,
  branchSha: string,
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
      "/repos/CUNY-AI-Lab/cail-identity/git/ref/tags/v5.2.0",
      { object: { sha: tagSha, type: "commit" } },
    ],
  ]);
  return async (path) => {
    if (!responses.has(path)) throw new Error(`unexpected API path: ${path}`);
    return responses.get(path);
  };
}

const exactReleaseContext = {
  packageVersion: "5.2.0",
  repository: "CUNY-AI-Lab/cail-identity",
  refType: "tag",
  refName: "v5.2.0",
  sha: releaseHead,
  expectedRuntimeSha256: runtimeSha256,
  actualRuntimeSha256: runtimeSha256,
  expectedPackagePayload: packagePayload,
  actualPackagePayload: packagePayload,
} as const;

describe("release version authority", () => {
  it("preserves the dated candidate observation separately from the published authority", () => {
    expect(isValidHistoricalAuthority(historicalAuthority)).toBe(true);
    expect(isValidPublishedAuthority(publishedAuthority)).toBe(true);
    expect(isValidCandidateAuthority(candidateAuthority)).toBe(true);
    expect(isValidCandidateSource(candidateAuthority.source)).toBe(true);
    expect(historicalAuthority.package.candidate_version).toBe("5.1.0");
    expect(candidateAuthority.package.candidate_version).toBe("5.2.0");
    expect(burnedCandidateAuthority.package.candidate_version).toBe("5.1.1");
    expect(burnedCandidateAuthority.source.tag).toBe("v5.1.1");
    expect(candidateAuthority.registry).not.toHaveProperty("workflow_receipt");
    expect(candidateAuthority.source).toEqual({
      tag: "v5.2.0",
      commit: reviewedBehaviorCommit,
      tree: reviewedBehaviorTree,
    });
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
    expect(
      isValidCandidateAuthority({
        ...candidateAuthority,
        source: { ...candidateAuthority.source, commit: "0".repeat(40) },
      }),
    ).toBe(false);
    expect(isValidCandidatePackagePayload(packagePayload)).toBe(true);
    expect(
      isValidCandidateAuthority({
        ...candidateAuthority,
        source: { ...candidateAuthority.source, extra: true },
      }),
    ).toBe(false);
    expect(isValidHistoricalAuthority(historicalAuthority)).toBe(true);
    expect(isValidPublishedAuthority(publishedAuthority)).toBe(true);
    expect(
      readFileSync(
        resolve(root, "evidence/package-release-authority-published.json"),
        "utf8",
      ),
    ).toBe(publishedAuthorityText);
  });

  it("derives the current runtime and validates source/tag and artifact identity", () => {
    expect(runtimeDigest()).toBe(
      "932dafab753fbae38c8cc37b76592835d880a764b98d51c602b9a0adc6323830",
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
            id: 1088911629,
            name: "5.2.0",
            created_at: "2026-08-07T16:37:20Z",
          },
        ],
        "5.2.0",
      ),
    ).toBe(false);
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

  it("accepts a release-only descendant with the reviewed behavior and payload", async () => {
    expect(releaseHead).not.toBe(reviewedBehaviorCommit);
    expect(reviewedBehaviorTree).toBe(
      candidateAuthority.behavior_authority.tree,
    );
    await expect(
      verifyReleaseRef(exactReleaseContext, releaseApi(releaseHead, releaseHead)),
    ).resolves.toBeUndefined();
  });

  it("rejects old, mismatched, drifted, or non-release refs", async () => {
    await expect(
      verifyReleaseRef(
        { ...exactReleaseContext, sha: oldHead },
        releaseApi(oldHead, releaseHead),
      ),
    ).rejects.toThrow("live default-branch head");
    await expect(
      verifyReleaseRef(
        { ...exactReleaseContext, sha: oldHead },
        releaseApi(releaseHead, releaseHead),
      ),
    ).rejects.toThrow("GITHUB_SHA is not the commit named by the release tag");
    await expect(
      verifyReleaseRef(
        exactReleaseContext,
        releaseApi(oldHead, releaseHead),
      ),
    ).rejects.toThrow("GITHUB_SHA is not the commit named by the release tag");
    await expect(
      verifyReleaseRef(
        { ...exactReleaseContext, actualRuntimeSha256: "0".repeat(64) },
        releaseApi(releaseHead, releaseHead),
      ),
    ).rejects.toThrow("runtime source differs");
    await expect(
      verifyReleaseRef(
        {
          ...exactReleaseContext,
          actualPackagePayload: {
            ...packagePayload,
            tarball_sha256: "0".repeat(64),
          },
        },
        releaseApi(releaseHead, releaseHead),
      ),
    ).rejects.toThrow("packed package payload differs");
    await expect(
      verifyReleaseRef(
        {
          ...exactReleaseContext,
          actualPackagePayload: {
            ...packagePayload,
            files: packagePayload.files.map((file: string) =>
              file === "src/testing.ts" ? "src/drift.ts" : file,
            ),
          },
        },
        releaseApi(releaseHead, releaseHead),
      ),
    ).rejects.toThrow("packed package payload differs");
    await expect(
      verifyReleaseRef(
        exactReleaseContext,
        releaseApi(releaseHead, oldHead),
      ),
    ).rejects.toThrow("live default-branch head");
    await expect(
      verifyReleaseRef(
        { ...exactReleaseContext, refType: "branch" },
        releaseApi(releaseHead, releaseHead),
      ),
    ).rejects.toThrow("requires a tag ref");
    await expect(
      verifyReleaseRef(
        { ...exactReleaseContext, refName: "v5.1.1" },
        releaseApi(releaseHead, releaseHead),
      ),
    ).rejects.toThrow("does not match package version");
  });

  it("keeps the live publish boundary explicit", () => {
    expect(packageJson.version).toBe("5.2.0");
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
    expect(releaseRefScript).toContain(
      "evidence/package-release-authority-candidate-5.2.0.json",
    );
    expect(releaseRefScript).not.toContain(
      "evidence/package-release-authority-candidate-5.1.1.json",
    );
    expect(releaseRefScript).not.toContain(
      "evidence/package-release-authority-published.json",
    );
    expect(publishWorkflow).toContain("bun run check:release-ref");
    expect(publishWorkflow).toContain("GITHUB_SHA: ${{ github.sha }}");
    expect(publishWorkflow).toContain(
      "GITHUB_REF_TYPE: ${{ github.ref_type }}",
    );
    expect(publishWorkflow).toContain(
      "GITHUB_REF_NAME: ${{ github.ref_name }}",
    );
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
      "run: bun publish --registry https://npm.pkg.github.com",
    );
    expect(publishWorkflow).not.toContain("NPM_CONFIG_REGISTRY");
    expect(ciWorkflow).toContain(
      "bun install --frozen-lockfile --ignore-scripts",
    );
  });

  it("keeps the publish recovery workflow fail-closed", () => {
    expect(publishWorkflow).toContain("workflow_dispatch:");
    expect(publishWorkflow).toContain("release_tag:");
    expect(publishWorkflow).toContain("type: string");
    expect(publishWorkflow).toContain(
      "DISPATCH_RELEASE_TAG: ${{ inputs.release_tag }}",
    );
    expect(publishWorkflow).toContain(
      "RELEASE_EVENT_TAG: ${{ github.event.release.tag_name }}",
    );
    expect(publishWorkflow).toContain('case "$EVENT_NAME" in');
    expect(publishWorkflow).toContain("release)");
    expect(publishWorkflow).toContain("workflow_dispatch)");
    expect(publishWorkflow).toContain(
      'if [[ ! "$release_tag" =~ ^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$ ]]; then',
    );
    expect(publishWorkflow).toContain(
      'if [[ "$EVENT_NAME" == "workflow_dispatch" ]]',
    );
    expect(publishWorkflow).toContain("jq -e '.immutable == true'");
    expect(publishWorkflow).toContain("/compare/${tag_sha}...${branch_sha}");
    expect(publishWorkflow).toContain(
      '(.status == "identical" or .status == "ahead")',
    );
    expect(publishWorkflow).toContain(".behind_by == 0");
    expect(publishWorkflow).toContain(
      "ref: ${{ github.event.repository.default_branch }}",
    );
    expect(publishWorkflow).toContain(
      "ref: ${{ steps.release.outputs.tag }}",
    );
    expect(publishWorkflow).toContain("fetch-depth: 0");
    expect(publishWorkflow).toContain("GITHUB_REF_TYPE: ${{ github.ref_type }}");
    expect(publishWorkflow).toContain("GITHUB_REF_NAME: ${{ github.ref_name }}");
    expect(publishWorkflow).toContain(
      "if: github.event_name == 'workflow_dispatch'",
    );
    expect(publishWorkflow).toContain(
      'expected_version="${RELEASE_TAG#v}"',
    );
    expect(publishWorkflow).toContain(
      'if: github.event_name == \'release\'',
    );
    expect(publishWorkflow).not.toContain("GITHUB_REF_TYPE: tag");
    expect(publishWorkflow).not.toContain(
      "GITHUB_REF_NAME: ${{ steps.release.outputs.tag }}",
    );
    expect(publishWorkflow).not.toContain(
      "GITHUB_SHA: ${{ steps.release.outputs.sha }}",
    );
    expect(publishWorkflow).not.toContain("github.event.inputs");
    expect(publishWorkflow).not.toContain("github.event.client_payload");
  });

  it("documents the immutable README defect in the already-published artifact", () => {
    expect(readme).toContain("immutable 5.1.0 artifact");
    expect(readme).toContain("cannot be edited");
    expect(readme).toContain("follow-up version");
    expect(readme).toContain("v5.1.1 GitHub release name was then burned");
    expect(readme).toContain("current candidate is v5.2.0");
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
      "+ @cuny-ai-lab/cail-identity@5.2.0 (dry-run)",
    );
    expect(existsSync(npmrc)).toBe(false);
  });
});
