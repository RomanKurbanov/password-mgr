import { build } from 'esbuild';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const output = await mkdtemp(join(project, '.test-run-'));

try {
  const files = (await readdir(join(project, 'tests')))
    .filter(name => name.endsWith('.test.ts')).sort();
  await build({
    absWorkingDir: project,
    entryPoints: files.map(name => join('tests', name)),
    outdir: output,
    bundle: true,
    packages: 'external',
    platform: 'node',
    format: 'esm',
    outExtension: { '.js': '.mjs' },
    target: 'node22',
    sourcemap: 'inline',
  });
  process.exitCode = await new Promise((resolveExit, reject) => {
    const child = spawn(process.execPath, ['--test', ...files.map(name =>
      join(output, name.replace(/\.ts$/, '.mjs')))], {
      cwd: project,
      stdio: 'inherit',
    });
    child.once('error', reject);
    child.once('exit', code => resolveExit(code ?? 1));
  });
} finally {
  await rm(output, { recursive: true, force: true });
}
