import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { test } from "node:test";
import semanticRelease from "semantic-release";
import config from "./release.config.js";

test("the actual semantic-release generator renders the configured preset", async () => {
  const require = createRequire(import.meta.url);
  const releaseRequire = createRequire(require.resolve("semantic-release"));
  const generatorPath = releaseRequire.resolve(
    "@semantic-release/release-notes-generator",
  );
  const { generateNotes } = await import(pathToFileURL(generatorPath));
  const [, options] = config.plugins.find(
    (plugin) =>
      Array.isArray(plugin) &&
      plugin[0] === "@semantic-release/release-notes-generator",
  );
  const hash = "1234567890abcdef1234567890abcdef12345678";
  const notes = await generateNotes(options, {
    cwd: process.cwd(),
    options: { repositoryUrl: config.repositoryUrl },
    branch: { name: "main" },
    lastRelease: { version: "1.0.0", gitTag: "1.0.0" },
    nextRelease: { version: "2.0.0", gitTag: "2.0.0" },
    commits: [
      { hash, message: "feat: parse application manifests" },
      { hash, message: "fix: recognize XML namespaces\n\nCloses #42" },
      {
        hash,
        message:
          "feat: distinguish manifest kinds\n\nBREAKING CHANGE: Manifest now exposes its kind.",
      },
    ],
    logger: { log() {}, error() {} },
  });
  for (const text of [
    "Features",
    "Bug Fixes",
    "BREAKING CHANGES",
    "parse application manifests",
    "recognize XML namespaces",
    "distinguish manifest kinds",
    "Manifest now exposes its kind.",
    "https://github.com/cmeister2/clickonce/compare/1.0.0...2.0.0",
    "https://github.com/cmeister2/clickonce/issues/42",
    `https://github.com/cmeister2/clickonce/commit/${hash}`,
  ]) {
    assert.ok(notes.includes(text), `release notes should contain ${text}`);
  }
});

test("the Cargo plugin prepares manifest and lockfile versions without publishing", async () => {
  const require = createRequire(import.meta.url);
  const pluginName = "@semantic-release-cargo/semantic-release-cargo";
  assert.ok(config.plugins.includes(pluginName));
  const pluginUrl = pathToFileURL(require.resolve(pluginName)).href;
  const directory = await mkdtemp(join(tmpdir(), "clickonce-release-"));
  try {
    await mkdir(join(directory, "src"));
    await writeFile(join(directory, "src", "lib.rs"), "//! Release preparation fixture.\n");
    await writeFile(
      join(directory, "Cargo.toml"),
      '[package]\nname = "clickonce-release-fixture"\nversion = "0.0.0"\nedition = "2024"\n',
    );
    await writeFile(
      join(directory, "Cargo.lock"),
      'version = 4\n\n[[package]]\nname = "clickonce-release-fixture"\nversion = "0.0.0"\n',
    );
    const result = spawnSync(
      process.execPath,
      [
        "--input-type=module",
        "--eval",
        `import plugin from ${JSON.stringify(pluginUrl)};
         await plugin.prepare({}, {
           nextRelease: { version: "1.2.3" },
           logger: { info() {}, warn() {}, error() {} },
         });`,
      ],
      { cwd: directory, encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    const manifest = await readFile(join(directory, "Cargo.toml"), "utf8");
    const lock = await readFile(join(directory, "Cargo.lock"), "utf8");
    assert.match(manifest, /^version = "1\.2\.3"$/m);
    assert.match(lock, /name = "clickonce-release-fixture"\nversion = "1\.2\.3"/);
    assert.doesNotMatch(manifest + lock, /version = "0\.0\.0"/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("a feature release advances beyond the legacy 0.0.x registry versions", async () => {
  const require = createRequire(import.meta.url);
  const releaseRequire = createRequire(require.resolve("semantic-release"));
  const analyzerName = "@semantic-release/commit-analyzer";
  const analyzer = config.plugins.find(
    (plugin) => (Array.isArray(plugin) ? plugin[0] : plugin) === analyzerName,
  );
  assert.ok(analyzer, "the configured commit analyzer must be exercised");
  const analyzerOptions = Array.isArray(analyzer) ? analyzer[1] : {};
  const directory = await mkdtemp(join(tmpdir(), "clickonce-version-"));
  const checkout = join(directory, "checkout");
  const remote = join(directory, "remote.git");
  // Ignore the host's CI branch, credentials, and Git configuration. Git may
  // access only the temporary local remote, even if a command is misconfigured.
  const env = {
    PATH: process.env.PATH,
    SystemRoot: process.env.SystemRoot,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: join(directory, "gitconfig"),
    GIT_CONFIG_COUNT: "0",
    GIT_ALLOW_PROTOCOL: "file",
    GIT_TERMINAL_PROMPT: "0",
    GIT_AUTHOR_NAME: "Release fixture",
    GIT_AUTHOR_EMAIL: "fixture@example.invalid",
    GIT_COMMITTER_NAME: "Release fixture",
    GIT_COMMITTER_EMAIL: "fixture@example.invalid",
  };
  const git = (cwd, ...args) => {
    const result = spawnSync(
      "git",
      ["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false", ...args],
      { cwd, env, encoding: "utf8" },
    );
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    return result.stdout.trim();
  };
  const output = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  try {
    git(directory, "init", "--bare", "--initial-branch=main", remote);
    git(directory, "init", "--initial-branch=main", checkout);
    git(checkout, "commit", "--allow-empty", "-m", "feat: baseline");
    git(checkout, "tag", "0.0.1");
    git(checkout, "remote", "add", "origin", remote);
    git(checkout, "push", "origin", "main", "--tags");

    for (const [message, type, version] of [
      ["fix: repair publishing", "patch", "0.0.2"],
      ["feat: publish the typed ClickOnce parser", "minor", "0.1.0"],
    ]) {
      git(checkout, "commit", "--allow-empty", "-m", message);
      git(checkout, "push", "origin", "main");
      const result = await semanticRelease(
        {
          ...config,
          repositoryUrl: remote,
          // Only analyze commits: never load Cargo or GitHub publication hooks.
          plugins: [[releaseRequire.resolve(analyzerName), analyzerOptions]],
          dryRun: true,
          ci: false,
        },
        { cwd: checkout, env, stdout: output, stderr: output },
      );
      assert.ok(result, "semantic-release should select a release");
      assert.equal(result.lastRelease.version, "0.0.1");
      assert.equal(result.nextRelease.type, type);
      assert.equal(result.nextRelease.version, version);
      assert.equal(result.nextRelease.gitTag, version);
      assert.equal(git(checkout, "tag", "--list"), "0.0.1");
      assert.equal(git(remote, "tag", "--list"), "0.0.1");
    }
  } finally {
    output.destroy();
    await rm(directory, { recursive: true, force: true });
  }
});
