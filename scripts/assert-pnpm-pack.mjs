/**
 * `exports` points at `src/index.ts` during development and is replaced with
 * the `dist` map by `publishConfig.exports` at publish time. That replacement
 * is a pnpm feature: `npm pack` and `npm publish` ignore it, and would ship a
 * package whose `exports` names a file that `files: ["dist"]` leaves out --
 * broken for every consumer, and not fixable once published.
 *
 * So refuse to be packed by anything but pnpm.
 */
const agent = process.env.npm_config_user_agent ?? ''

if (!agent.startsWith('pnpm/')) {
  const client = agent.split(' ')[0] || 'an unknown client'

  console.error(
    `\nRefusing to pack with ${client}.\n\n` +
      'npm does not apply publishConfig.exports, so the tarball would point at\n' +
      'src/index.ts, which is not published. Use pnpm:\n\n' +
      '  pnpm release\n'
  )

  process.exit(1)
}
