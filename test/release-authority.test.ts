import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  isValidAuthority,
  isValidLiveVersions,
  runtimeDigest,
} from "../scripts/check-release-authority.js";

const authority = JSON.parse(
  readFileSync(
    resolve(
      import.meta.dirname,
      "../evidence/package-release-authority.json",
    ),
    "utf8",
  ),
);
const packageJson = JSON.parse(
  readFileSync(
    resolve(import.meta.dirname, "../package.json"),
    "utf8",
  ),
);
const publishWorkflow = readFileSync(
  resolve(import.meta.dirname, "../.github/workflows/publish.yml"),
  "utf8",
);
const ciWorkflow = readFileSync(
  resolve(import.meta.dirname, "../.github/workflows/ci.yml"),
  "utf8",
);

describe("release version authority", () => {
  it("records the occupied release and preserves behavior bytes", () => {
    expect(isValidAuthority(authority)).toBe(true);
    expect(runtimeDigest()).toBe(
      "2300e88d443a6badb87dc34b73bcb8f41fc3e53f740938357d1e490fb06ea93a",
    );
  });

  it("rechecks live authority immediately before a future publish", () => {
    expect(packageJson.version).toBe("5.1.0");
    expect(packageJson.scripts.prepublishOnly).toContain(
      "bun run check:clean",
    );
    expect(packageJson.scripts.prepublishOnly).toContain(
      "bun run check:release-live",
    );
    expect(publishWorkflow).toContain(
      "/orgs/CUNY-AI-Lab/packages/npm/cail-identity/versions",
    );
    expect(publishWorkflow).toContain(
      'CAIL_REGISTRY_VERSIONS_FILE="$RUNNER_TEMP/cail-identity-package-versions.json"',
    );
    expect(ciWorkflow).toContain(
      "bun install --frozen-lockfile --ignore-scripts",
    );
    expect(publishWorkflow).toContain(
      "NPM_CONFIG_TOKEN: ${{ secrets.GITHUB_TOKEN }}",
    );
    expect(publishWorkflow).not.toContain("NODE_AUTH_TOKEN");
    expect(publishWorkflow).not.toContain("NPM_CONFIG_USERCONFIG");
    expect(publishWorkflow).not.toMatch(/>\s*\.npmrc/);
    expect(publishWorkflow).toContain(
      "NPM_CONFIG_REGISTRY: https://npm.pkg.github.com",
    );
  });

  it("uses Bun's token authority without writing checkout credentials", () => {
    const npmrc = resolve(import.meta.dirname, "../.npmrc");
    expect(existsSync(npmrc)).toBe(false);
    const result = spawnSync(
      "bun",
      ["publish", "--dry-run", "--ignore-scripts"],
      {
        cwd: resolve(import.meta.dirname, ".."),
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
      "+ @cuny-ai-lab/cail-identity@5.1.0 (dry-run)",
    );
    expect(existsSync(npmrc)).toBe(false);
  });

  it("rejects forged local authority", () => {
    expect(
      isValidAuthority({
        ...authority,
        package: { ...authority.package, candidate_version: "5.0.0" },
      }),
    ).toBe(false);
    expect(
      isValidAuthority({
        ...authority,
        registry: {
          ...authority.registry,
          candidate_state: "not_published",
          workflow_receipt: authority.registry.workflow_receipt,
          candidate_state_scope: "current_registry_state",
        },
      }),
    ).toBe(false);
    expect(
      isValidAuthority({
        ...authority,
        registry: {
          ...authority.registry,
          candidate_state: "published",
          workflow_receipt: {
            ...authority.registry.workflow_receipt,
            commit: "forged",
          },
        },
      }),
    ).toBe(false);
  });

  it("records a bounded workflow receipt without claiming registry availability", () => {
    expect(authority.registry.candidate_state).toBe("not_published");
    expect(authority.registry.candidate_state_scope).toBe(
      "last_registry_observation",
    );
    expect(authority.registry.workflow_receipt).toMatchObject({
      source: "github-actions-publish-workflow",
      claim: "workflow_completed_successfully_registry_unverified",
      observed_at: "2026-08-01T18:40:58Z",
      workflow_run_id: 30709375309,
      workflow_job_id: 91394005405,
      run_status: "completed",
      run_conclusion: "success",
      tag: "v5.1.0",
      commit: "15f3c6b92c79ab13a9d84df1061d72fabe4ad5e9",
      published_at: "2026-08-01T17:00:16Z",
    });
  });

  it("requires a non-null plain receipt with the exact closed key set", () => {
    const receipt = authority.registry.workflow_receipt;
    const cases = [
      ["missing", (() => {
        const registry = { ...authority.registry };
        delete registry.workflow_receipt;
        return registry;
      })()],
      ["null", { ...authority.registry, workflow_receipt: null }],
      ["array", { ...authority.registry, workflow_receipt: [] }],
      ["extra", {
        ...authority.registry,
        workflow_receipt: { ...receipt, extra: true },
      }],
      ["mismatched", {
        ...authority.registry,
        workflow_receipt: { ...receipt, run_conclusion: "failure" },
      }],
    ] as const;
    for (const [label, registry] of cases) {
      const candidate = { ...authority, registry };
      expect(() => isValidAuthority(candidate), label).not.toThrow();
      expect(isValidAuthority(candidate), label).toBe(false);
    }
  });

  it("requires the exact old registry identity and candidate absence", () => {
    const live = [
      {
        id: 1066308573,
        name: "5.0.0",
        created_at: "2026-07-25T17:27:05Z",
      },
    ];
    expect(isValidLiveVersions(live)).toBe(true);
    expect(
      isValidLiveVersions([
        ...live,
        {
          id: 1,
          name: "5.1.0",
          created_at: "2026-07-25T18:00:00Z",
        },
      ]),
    ).toBe(false);
    expect(
      isValidLiveVersions([{ ...live[0], id: 1066308574 }]),
    ).toBe(false);
  });
});
