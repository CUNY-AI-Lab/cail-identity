import { existsSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dir, "..");

function git(args: string[]): string {
  const result = Bun.spawnSync({
    cmd: ["git", "--no-replace-objects", ...args],
    cwd: root,
    stdout: "pipe",
    stderr: "pipe",
  });
  if (result.exitCode !== 0) {
    throw new Error("cail-identity: could not verify publication checkout");
  }
  return result.stdout.toString();
}

const inside = git(["rev-parse", "--is-inside-work-tree"]).trim();
if (inside !== "true") {
  throw new Error(
    "cail-identity: publication requires a Git checkout; source archives may run `bun run check` but cannot publish",
  );
}
if (git(["for-each-ref", "--format=%(refname)", "refs/replace"]).trim()) {
  throw new Error("cail-identity: publication rejects Git replacement refs");
}
const grafts = git(["rev-parse", "--git-path", "info/grafts"]).trim();
if (grafts && existsSync(resolve(root, grafts))) {
  throw new Error("cail-identity: publication rejects legacy Git grafts");
}
if (git(["status", "--porcelain", "--untracked-files=all"]).length > 0) {
  throw new Error("cail-identity: publication requires a clean Git worktree");
}
for (const line of git(["ls-files", "-v"]).split("\n")) {
  if (line && !line.startsWith("H ")) {
    throw new Error(
      "cail-identity: publication rejects nonordinary Git index flags",
    );
  }
}
