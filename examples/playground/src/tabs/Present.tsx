import { CoseKey, DeviceRequest, DocRequest, Holder, IssuerSigned, ItemsRequest, SessionTranscript } from '@m-doc/core'
import { AlertTriangle, Loader2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { CopyButton } from '@/components/JsonPane'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { ctx, describeError, encodeBase64Url, parseInput } from '@/lib/mdoc'

export const Present = ({
  issuerSigned,
  devicePrivateKeyJwk,
  onIssuerSigned,
  onDeviceKey,
  onPresented,
}: {
  issuerSigned: string
  devicePrivateKeyJwk: string
  onIssuerSigned: (value: string) => void
  onDeviceKey: (value: string) => void
  onPresented: (value: string) => void
}) => {
  const [clientId, setClientId] = useState('x509_san_dns:verifier.example.com')
  const [responseUri, setResponseUri] = useState('https://verifier.example.com/openid4vp/response')
  const [nonce, setNonce] = useState('n-0S6_WzA2Mj')
  const [selected, setSelected] = useState<Record<string, boolean>>({})
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [result, setResult] = useState<string>()

  /** What the held document could disclose, so the request can name a subset. */
  const available = useMemo(() => {
    if (!issuerSigned.trim()) return undefined

    try {
      const decoded = IssuerSigned.decode(parseInput(issuerSigned))
      const claims = decoded.getAllPrettyClaims()
      const [namespace] = decoded.namespaces

      return {
        docType: decoded.issuerAuth.mobileSecurityObject.docType,
        namespace,
        elements: namespace ? Object.keys(claims[namespace] ?? {}) : [],
      }
    } catch {
      return undefined
    }
  }, [issuerSigned])

  const isSelected = (element: string) => selected[element] ?? true

  const present = async () => {
    setBusy(true)
    setError(undefined)

    try {
      if (!available?.namespace) throw new Error('Load an IssuerSigned document first')

      const disclosed = available.elements.filter(isSelected)
      if (disclosed.length === 0) throw new Error('Select at least one element to disclose')

      const deviceRequest = new DeviceRequest({
        docRequests: [
          new DocRequest({
            itemsRequest: new ItemsRequest({
              docType: available.docType,
              namespaces: {
                [available.namespace]: Object.fromEntries(disclosed.map((element) => [element, false])),
              },
            }),
          }),
        ],
      })

      const sessionTranscript = await SessionTranscript.forOid4Vp({ clientId, responseUri, nonce }, ctx)

      const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
        {
          deviceRequest,
          sessionTranscript,
          issuerSigned: [IssuerSigned.decode(parseInput(issuerSigned))],
          signature: { signingKey: CoseKey.fromJwk(JSON.parse(devicePrivateKeyJwk)) },
        },
        ctx
      )

      const encoded = encodeBase64Url(deviceResponse.encode())
      setResult(encoded)
      onPresented(encoded)
    } catch (presentError) {
      setError(describeError(presentError))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card>
        <CardHeader>
          <CardTitle>Held document</CardTitle>
          <CardDescription>The IssuerSigned to present, and the device key bound to it.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex flex-col gap-1">
            <Label>IssuerSigned (base64url)</Label>
            <Textarea
              rows={5}
              spellCheck={false}
              value={issuerSigned}
              placeholder="Issue one in the Issue tab, or paste your own"
              onChange={(event) => onIssuerSigned(event.target.value)}
            />
          </div>

          <div className="flex flex-col gap-1">
            <Label>device private key (JWK)</Label>
            <Textarea
              rows={5}
              spellCheck={false}
              value={devicePrivateKeyJwk}
              placeholder='{ "kty": "EC", "crv": "P-256", "d": "…" }'
              onChange={(event) => onDeviceKey(event.target.value)}
            />
          </div>

          {available && (
            <div className="flex flex-col gap-2">
              <Label>disclose</Label>
              <div className="flex flex-wrap gap-1.5">
                {available.elements.map((element) => (
                  <button
                    key={element}
                    type="button"
                    onClick={() => setSelected((current) => ({ ...current, [element]: !isSelected(element) }))}
                    className={`rounded-md border px-2 py-1 font-mono text-xs transition-colors ${
                      isSelected(element)
                        ? 'border-accent bg-accent/15 text-accent'
                        : 'border-line text-muted hover:text-ink'
                    }`}
                  >
                    {element}
                  </button>
                ))}
              </div>
              <p className="text-xs text-muted">
                Only the selected elements go into the response — the rest stay behind, digests and all.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="flex flex-col gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Session transcript</CardTitle>
            <CardDescription>OpenID4VP 1.0. The response is bound to these three values.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-col gap-1">
              <Label>client_id</Label>
              <Input className="font-mono" value={clientId} onChange={(event) => setClientId(event.target.value)} />
            </div>
            <div className="flex flex-col gap-1">
              <Label>response_uri</Label>
              <Input
                className="font-mono"
                value={responseUri}
                onChange={(event) => setResponseUri(event.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1">
              <Label>nonce</Label>
              <Input className="font-mono" value={nonce} onChange={(event) => setNonce(event.target.value)} />
            </div>
            <Button onClick={() => void present()} disabled={busy || !available}>
              {busy && <Loader2 className="animate-spin" />}
              Present
            </Button>
          </CardContent>
        </Card>

        {error && (
          <Card className="border-bad/40">
            <CardContent className="flex items-start gap-2 text-sm text-bad">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span className="break-all">{error}</span>
            </CardContent>
          </Card>
        )}

        {result && (
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle>DeviceResponse</CardTitle>
              <div className="flex items-center gap-2">
                <Badge tone="good">base64url</Badge>
                <CopyButton value={result} />
              </div>
            </CardHeader>
            <CardContent>
              <pre className="max-h-64 overflow-auto rounded-md border border-line bg-bg p-3 font-mono text-xs break-all whitespace-pre-wrap">
                {result}
              </pre>
              <p className="mt-2 text-xs text-muted">Carried to the Decode tab automatically.</p>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
