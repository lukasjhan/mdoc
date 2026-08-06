import { SignedVical } from '@m-doc/vical'
import { AlertTriangle, ShieldCheck, ShieldX } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { FileButton, useFileDrop } from '@/components/FileLoader'
import { CopyButton, Field } from '@/components/JsonPane'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Textarea } from '@/components/ui/textarea'
import { ctx, describeError, formatBytes, parseInput } from '@/lib/mdoc'

export const VicalTab = ({ input, onInput }: { input: string; onInput: (value: string) => void }) => {
  const [verified, setVerified] = useState<boolean | undefined>()
  const [fileError, setFileError] = useState<string>()

  const file = { onLoad: onInput, onError: setFileError, accept: '.vical,.cbor,.bin,.txt' }
  const drop = useFileDrop(file)

  const result = useMemo(() => {
    if (!input.trim()) return undefined

    try {
      const signed = SignedVical.decode(parseInput(input))

      return { ok: true as const, signed, vical: signed.vical }
    } catch (error) {
      return { ok: false as const, error: describeError(error) }
    }
  }, [input])

  useEffect(() => {
    setVerified(undefined)

    if (!result?.ok) return

    let cancelled = false
    result.signed
      .verify({}, ctx)
      .then((valid) => !cancelled && setVerified(valid))
      .catch(() => !cancelled && setVerified(false))

    return () => {
      cancelled = true
    }
  }, [result])

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
      <Card>
        <CardHeader className="flex-row items-start justify-between gap-4">
          <div className="flex flex-col gap-1.5">
            <CardTitle>VICAL</CardTitle>
            <CardDescription>
              The ISO/IEC 18013-5 Annex C issuer trust list, as hex, base64 or base64url — or drop the file itself.
            </CardDescription>
          </div>
          <FileButton {...file} />
        </CardHeader>
        <CardContent>
          <div className="relative" {...drop.handlers}>
            <Textarea
              rows={22}
              spellCheck={false}
              value={input}
              placeholder="d28443a10126a1182159…"
              onChange={(event) => {
                setFileError(undefined)
                onInput(event.target.value)
              }}
            />
            {drop.over && (
              <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-md border-2 border-dashed border-accent bg-bg/80 text-sm font-medium">
                Drop the VICAL
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="flex flex-col gap-4">
        {fileError && (
          <Card className="border-bad/40">
            <CardContent className="flex items-start gap-2 text-sm text-bad">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span className="break-all">{fileError}</span>
            </CardContent>
          </Card>
        )}

        {result && !result.ok && (
          <Card className="border-bad/40">
            <CardContent className="flex items-start gap-2 text-sm text-bad">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span className="break-all">{result.error}</span>
            </CardContent>
          </Card>
        )}

        {result?.ok && (
          <>
            <Card>
              <CardHeader className="flex-row items-center justify-between">
                <CardTitle>{result.vical.vicalProvider}</CardTitle>
                {verified === undefined ? (
                  <Badge>checking…</Badge>
                ) : verified ? (
                  <Badge tone="good">
                    <ShieldCheck className="mr-1 size-3" /> signature valid
                  </Badge>
                ) : (
                  <Badge tone="bad">
                    <ShieldX className="mr-1 size-3" /> signature invalid
                  </Badge>
                )}
              </CardHeader>
              <CardContent className="py-1">
                <Field label="version">{result.vical.version}</Field>
                <Field label="date">{result.vical.date.toISOString()}</Field>
                {result.vical.nextUpdate && <Field label="next update">{result.vical.nextUpdate.toISOString()}</Field>}
                {result.vical.vicalIssueID !== undefined && <Field label="issue id">{result.vical.vicalIssueID}</Field>}
                <Field label="entries">{result.vical.certificateInfos.length}</Field>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Certificates</CardTitle>
                <CardDescription>
                  Verifying against the certificate the list carries says only that it is internally consistent.
                </CardDescription>
              </CardHeader>
              <CardContent className="flex max-h-[26rem] flex-col gap-2 overflow-auto">
                {result.vical.certificateInfos.map((info) => (
                  <div
                    key={`${info.issuingCountry}-${info.serialNumber}`}
                    className="rounded-md border border-line bg-bg p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-medium">
                        {info.issuingAuthority ?? info.issuingCountry ?? 'unnamed'}
                      </span>
                      <div className="flex gap-1">
                        {info.issuingCountry && <Badge tone="accent">{info.issuingCountry}</Badge>}
                        <CopyButton value={info.toPem()} />
                      </div>
                    </div>
                    <dl className="mt-2 grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1 font-mono text-[0.7rem] text-muted">
                      <dt>serial</dt>
                      <dd className="break-all text-ink">{info.serialNumber.toString()}</dd>
                      <dt>ski</dt>
                      <dd className="break-all text-ink">{formatBytes(info.ski, 20)}</dd>
                      <dt>docType</dt>
                      <dd className="break-all text-ink">{info.docType.join(', ')}</dd>
                      {info.notAfter && (
                        <>
                          <dt>not after</dt>
                          <dd className="text-ink">{info.notAfter.toISOString().slice(0, 10)}</dd>
                        </>
                      )}
                    </dl>
                  </div>
                ))}
              </CardContent>
            </Card>
          </>
        )}

        {!result && (
          <Card>
            <CardContent className="text-sm text-muted">
              Paste or upload a VICAL to decode it and check its signature. Nothing leaves the browser.
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
