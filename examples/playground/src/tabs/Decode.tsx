import { DeviceResponse, type IssuerAuth, IssuerSigned } from '@m-doc/core'
import { AlertTriangle } from 'lucide-react'
import { useMemo } from 'react'
import { Field, JsonPane } from '@/components/JsonPane'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { describeError, formatBytes, parseInput, stringify } from '@/lib/mdoc'

type Decoded = {
  kind: 'DeviceResponse' | 'IssuerSigned'
  claims: unknown
  issuerAuth: IssuerAuth
  docType: string
  namespaces: Array<string>
  status?: number
}

/**
 * A DeviceResponse and a bare IssuerSigned both turn up in the wild — the first
 * from a presentation, the second from OpenID4VCI — so both are tried.
 */
const decode = (bytes: Uint8Array): Decoded => {
  try {
    const response = DeviceResponse.decode(bytes)
    const document = response.documents?.[0]

    if (!document) throw new Error('The DeviceResponse carries no documents')

    return {
      kind: 'DeviceResponse',
      claims: response.getAllPrettyClaimsAsJson(),
      issuerAuth: document.issuerSigned.issuerAuth,
      docType: document.docType,
      namespaces: document.namespaces,
      status: response.status,
    }
  } catch (responseError) {
    try {
      const issuerSigned = IssuerSigned.decode(bytes)

      return {
        kind: 'IssuerSigned',
        claims: issuerSigned.getAllPrettyClaimsAsJson(),
        issuerAuth: issuerSigned.issuerAuth,
        docType: issuerSigned.issuerAuth.mobileSecurityObject.docType,
        namespaces: issuerSigned.namespaces,
      }
    } catch {
      // The DeviceResponse error is the more informative of the two
      throw responseError
    }
  }
}

export const Decode = ({ input, onInput }: { input: string; onInput: (value: string) => void }) => {
  const result = useMemo(() => {
    if (!input.trim()) return undefined

    try {
      return { ok: true as const, value: decode(parseInput(input)) }
    } catch (error) {
      return { ok: false as const, error: describeError(error) }
    }
  }, [input])

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <Card>
        <CardHeader>
          <CardTitle>Encoded document</CardTitle>
          <CardDescription>A DeviceResponse or IssuerSigned, as hex, base64 or base64url.</CardDescription>
        </CardHeader>
        <CardContent>
          <Textarea
            rows={22}
            value={input}
            spellCheck={false}
            placeholder="o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOB…"
            onChange={(event) => onInput(event.target.value)}
          />
        </CardContent>
      </Card>

      <div className="flex flex-col gap-4">
        {result && !result.ok && (
          <Card className="border-bad/40">
            <CardContent className="flex items-start gap-2 text-sm text-bad">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span className="break-all">{result.error}</span>
            </CardContent>
          </Card>
        )}

        {result?.ok && <Decoded value={result.value} />}

        {!result && (
          <Card>
            <CardContent className="text-sm text-muted">
              Paste a document to decode it. Nothing leaves the browser.
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}

const Decoded = ({ value }: { value: Decoded }) => {
  const mso = value.issuerAuth.mobileSecurityObject
  const validity = mso.validityInfo
  const now = new Date()
  const expired = validity.validUntil.getTime() < now.getTime()

  return (
    <>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>{value.kind}</CardTitle>
          <div className="flex gap-2">
            <Badge tone="accent">{mso.digestAlgorithm}</Badge>
            <Badge tone={expired ? 'bad' : 'good'}>{expired ? 'expired' : 'within validity'}</Badge>
          </div>
        </CardHeader>
        <CardContent className="py-1">
          <Field label="docType">{value.docType}</Field>
          <Field label="namespaces">{value.namespaces.join(', ') || '—'}</Field>
          <Field label="signed">{validity.signed.toISOString()}</Field>
          <Field label="valid from">{validity.validFrom.toISOString()}</Field>
          <Field label="valid until">{validity.validUntil.toISOString()}</Field>
          {validity.expectedUpdate && <Field label="expected update">{validity.expectedUpdate.toISOString()}</Field>}
          {value.status !== undefined && <Field label="response status">{value.status}</Field>}
          <Field label="device key">{formatBytes(mso.deviceKeyInfo.deviceKey.encode(), 24)}</Field>
          {mso.status?.statusList && (
            <Field label="status list">
              idx {mso.status.statusList.idx} · {mso.status.statusList.uri}
            </Field>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Claims</CardTitle>
          <CardDescription>Byte strings are shown base64url; dates as they encode.</CardDescription>
        </CardHeader>
        <CardContent>
          <JsonPane value={stringify(value.claims)} />
        </CardContent>
      </Card>
    </>
  )
}
