/**
 * What the tarballs actually look like to a consumer.
 *
 * Linting the source directory is not enough: `exports` only becomes the dist
 * map at pack time, so both publint and attw have to run against a real pnpm
 * tarball or they see `src/index.ts` and report nonsense.
 */

import { execFileSync } from 'node:child_process'
import { mkdirSync, readdirSync, rmSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const out = join(root, '.packs')

const run = (command, args, cwd) => execFileSync(command, args, { cwd, encoding: 'utf8', stdio: 'pipe' })

rmSync(out, { recursive: true, force: true })
mkdirSync(out, { recursive: true })

const packages = readdirSync(join(root, 'packages'))
let failed = 0

for (const name of packages) {
  const dir = join(root, 'packages', name)

  process.stdout.write(`${name.padEnd(10)} `)

  let tarball
  try {
    const output = run('pnpm', ['pack', '--pack-destination', out], dir)
    tarball = output
      .trim()
      .split('\n')
      .find((line) => line.endsWith('.tgz'))
    if (!tarball) throw new Error(`no tarball in:\n${output}`)
  } catch (error) {
    console.log(`pack failed\n${error.stdout ?? error.message}`)
    failed++
    continue
  }

  const results = []

  for (const [label, args] of [
    ['publint', ['publint', tarball]],
    ['attw', ['@arethetypeswrong/cli', tarball, '--format', 'table-flipped']],
  ]) {
    try {
      run('npx', ['--yes', ...args], root)
      results.push(`${label} ok`)
    } catch (error) {
      results.push(`${label} FAILED`)
      failed++
      console.log(`\n${error.stdout ?? error.message}`)
    }
  }

  console.log(results.join('  '))
}

rmSync(out, { recursive: true, force: true })

if (failed > 0) {
  console.error(`\n${failed} check(s) failed`)
  process.exit(1)
}

console.log('\nEvery package resolves for CJS, ESM, node10 and bundlers.')
