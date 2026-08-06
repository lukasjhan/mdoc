import { createMdocContext } from '@m-doc/context'
import { base64url, cborToJson, hex, type JsonValue } from '@m-doc/core'

export const ctx = createMdocContext()

/**
 * Reads whatever the user pasted. mdocs travel as base64url in OpenID4VP and
 * OpenID4VCI, as plain base64 in some tooling, and as hex in test vectors, so
 * all three are accepted and the whitespace people paste along with them is
 * dropped.
 */
export const parseInput = (input: string): Uint8Array => {
  const trimmed = input.replace(/\s+/g, '')

  if (trimmed.length === 0) throw new Error('Nothing to decode')

  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    return hex.decode(trimmed)
  }

  if (/^[A-Za-z0-9_-]+$/.test(trimmed)) {
    return base64url.decode(trimmed)
  }

  if (/^[A-Za-z0-9+/]+=*$/.test(trimmed)) {
    // Plain base64 — convert to the base64url alphabet
    return base64url.decode(trimmed.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''))
  }

  throw new Error('Input is not hex, base64 or base64url')
}

/**
 * Reads a dropped or picked file. A `.txt` holds one of the encodings above, so
 * it is passed through as typed; anything else is taken to be the raw CBOR.
 */
export const readFileAsInput = async (file: File): Promise<string> => {
  const bytes = new Uint8Array(await file.arrayBuffer())

  if (bytes.length === 0) throw new Error(`${file.name} is empty`)

  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim()
    parseInput(text)

    return text
  } catch {
    return base64url.encode(bytes)
  }
}

export const toJson = (value: unknown): JsonValue => cborToJson(value, { bytes: 'base64url' })

export const stringify = (value: unknown): string => JSON.stringify(toJson(value), null, 2)

export const encodeBase64Url = (bytes: Uint8Array): string => base64url.encode(bytes)

export const formatBytes = (bytes: Uint8Array, limit = 64): string => {
  const encoded = hex.encode(bytes)

  return encoded.length > limit * 2 ? `${encoded.slice(0, limit * 2)}… (${bytes.length} bytes)` : encoded
}

export const describeError = (error: unknown): string =>
  error instanceof Error ? error.message : typeof error === 'string' ? error : 'Unknown error'
