import { createMdocContext } from '@m-doc/context'
import { hex, type MdocContext } from '../src'

export const mdocContext: MdocContext = createMdocContext()

export const deterministicMdocContext = {
  ...mdocContext,
  crypto: {
    ...mdocContext.crypto,
    random: (len: number) =>
      hex.decode('9bdb72498967865710108af43959f90c1b6aac9687bedd1fa53dd0d2103fa5d0').slice(0, len),
  },
}
