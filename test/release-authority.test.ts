import { readFileSync } from "node:fs";
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

describe("release version authority", () => {
  it("records the occupied release and preserves behavior bytes", () => {
    expect(isValidAuthority(authority)).toBe(true);
    expect(runtimeDigest()).toBe(
      "37a34bf368b87a13680b6294f64be5b303ac1c6e9d4d58505cf9591531f3dbe3",
    );
  });

  it("rechecks live authority immediately before a future publish", () => {
    expect(packageJson.version).toBe("5.0.1");
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
          name: "5.0.1",
          created_at: "2026-07-25T18:00:00Z",
        },
      ]),
    ).toBe(false);
    expect(
      isValidLiveVersions([{ ...live[0], id: 1066308574 }]),
    ).toBe(false);
  });
});
