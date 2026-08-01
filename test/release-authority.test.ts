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
          candidate_state: "published",
        },
      }),
    ).toBe(false);
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
