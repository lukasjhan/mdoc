import { DateOnly, Issuer } from '@m-doc/core'
import { buildAgeAttestations, MDL_DOC_TYPE, MDL_NAMESPACE, encodingFor as mdlEncodingFor } from '@m-doc/mdl'
import { PHOTO_ID_BASE_NAMESPACE, PHOTO_ID_DOC_TYPE, encodingFor as photoIdEncodingFor } from '@m-doc/photo-id'
import { AlertTriangle, Loader2, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { CopyButton, Field } from '@/components/JsonPane'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ES256, generateDeviceKey, generateIssuer } from '@/lib/keys'
import { ctx, describeError, encodeBase64Url, parseInput } from '@/lib/mdoc'

type Claim = { id: number; name: string; value: string }

// The names ISO/IEC 18013-5 D.2.1 and ISO/IEC TS 23220-4 use in their examples
const PROFILES = {
  mDL: {
    docType: MDL_DOC_TYPE,
    namespace: MDL_NAMESPACE,
    encodingFor: mdlEncodingFor,
    claims: [
      { name: 'family_name', value: 'Doe' },
      { name: 'given_name', value: 'Jane' },
      { name: 'birth_date', value: '1990-04-12' },
      { name: 'issue_date', value: '2024-01-01' },
      { name: 'expiry_date', value: '2034-01-01' },
      { name: 'issuing_country', value: 'NL' },
      { name: 'issuing_authority', value: 'RDW' },
      { name: 'document_number', value: 'NL-2024-000123' },
      { name: 'un_distinguishing_sign', value: 'NL' },
    ],
  },
  PhotoID: {
    docType: PHOTO_ID_DOC_TYPE,
    namespace: PHOTO_ID_BASE_NAMESPACE,
    encodingFor: photoIdEncodingFor,
    claims: [
      { name: 'family_name', value: 'Doe' },
      { name: 'given_name', value: 'Jane' },
      { name: 'birth_date', value: '1990-04-12' },
      { name: 'issue_date', value: '2024-01-01' },
      { name: 'expiry_date', value: '2034-01-01' },
      { name: 'issuing_authority', value: 'IND' },
      { name: 'issuing_country', value: 'NL' },
    ],
  },
} as const

type ProfileName = keyof typeof PROFILES

const toClaims = (profile: ProfileName): Array<Claim> => PROFILES[profile].claims.map((claim, id) => ({ id, ...claim }))

/**
 * The encoding is the profile's to decide, not the user's — every element the
 * two specifications name has one fixed encoding. An element neither of them
 * names falls back to a text string.
 */
const encodingOf = (profile: ProfileName, name: string) => PROFILES[profile].encodingFor(name.trim()) ?? 'tstr'

// Table 5 allows either for the two date elements; a full-date is what we write
const LABELS: Record<string, string> = { 'tdate-or-full-date': 'full-date' }

const coerce = (encoding: string, value: string): unknown => {
  if (encoding === 'full-date' || encoding === 'tdate-or-full-date') return new DateOnly(value)
  if (encoding === 'tdate') return new Date(value)
  if (encoding === 'uint') return Number(value)
  if (encoding === 'bool') return value === 'true'
  if (encoding === 'bstr') return parseInput(value)

  return value
}

export type IssueResult = { encoded: string; certificatePem: string; devicePrivateKeyJwk: string }

export const Issue = ({ onIssued }: { onIssued: (result: IssueResult) => void }) => {
  const [profile, setProfile] = useState<ProfileName>('mDL')
  const [claims, setClaims] = useState<Array<Claim>>(() => toClaims('mDL'))
  const [ages, setAges] = useState('18, 21')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string>()
  const [result, setResult] = useState<IssueResult>()

  const selectProfile = (next: ProfileName) => {
    setProfile(next)
    setClaims(toClaims(next))
    setResult(undefined)
  }

  const issue = async () => {
    setBusy(true)
    setError(undefined)

    try {
      const { docType, namespace } = PROFILES[profile]
      const validFrom = new Date()
      const validUntil = new Date(Date.now() + 10 * 365 * 24 * 60 * 60 * 1000)

      const values: Record<string, unknown> = {}
      for (const claim of claims) {
        const name = claim.name.trim()
        if (name) values[name] = coerce(encodingOf(profile, name), claim.value)
      }

      // 7.2.5 wants the age attestations evaluated at the MSO's validFrom
      const birthDate = claims.find((claim) => claim.name === 'birth_date')?.value
      const requested = ages
        .split(',')
        .map((age) => Number(age.trim()))
        .filter((age) => Number.isInteger(age) && age >= 0 && age <= 99)

      if (birthDate && requested.length > 0) {
        Object.assign(values, buildAgeAttestations(birthDate, validFrom, requested))
      }

      const [issuer, device] = await Promise.all([generateIssuer(), generateDeviceKey()])

      const issuerSigned = await new Issuer(docType, ctx).addIssuerNamespace(namespace, values).sign({
        signingKey: issuer.signingKey,
        certificate: issuer.certificate,
        algorithm: ES256,
        digestAlgorithm: 'SHA-256',
        deviceKeyInfo: { deviceKey: device.publicKey },
        validityInfo: { signed: validFrom, validFrom, validUntil },
      })

      const issued: IssueResult = {
        encoded: encodeBase64Url(issuerSigned.encode()),
        certificatePem: issuer.certificatePem,
        devicePrivateKeyJwk: JSON.stringify(device.privateKey.jwk, null, 2),
      }

      setResult(issued)
      onIssued(issued)
    } catch (issueError) {
      setError(describeError(issueError))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <Card>
        <CardHeader>
          <CardTitle>Document</CardTitle>
          <CardDescription>
            Signed with a freshly generated key and a self-signed certificate — good for decoding, trusted by nobody.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <div className="flex gap-2">
            {(Object.keys(PROFILES) as Array<ProfileName>).map((name) => (
              <Button
                key={name}
                size="sm"
                variant={profile === name ? 'default' : 'outline'}
                onClick={() => selectProfile(name)}
              >
                {name}
              </Button>
            ))}
          </div>

          <div className="flex flex-col gap-1">
            <Label>namespace</Label>
            <code className="rounded-md border border-line bg-bg px-3 py-2 font-mono text-xs">
              {PROFILES[profile].namespace}
            </code>
          </div>

          <div className="flex flex-col gap-2">
            <Label>claims</Label>
            <p className="-mt-1 text-xs text-muted">
              The encoding on the right is fixed by the specification for that element identifier.
            </p>
            {claims.map((claim) => (
              <div key={claim.id} className="flex gap-2">
                <Input
                  className="flex-1 font-mono"
                  value={claim.name}
                  placeholder="element identifier"
                  onChange={(event) =>
                    setClaims((current) =>
                      current.map((c) => (c.id === claim.id ? { ...c, name: event.target.value } : c))
                    )
                  }
                />
                <Input
                  className="flex-1 font-mono"
                  value={claim.value}
                  placeholder="value"
                  onChange={(event) =>
                    setClaims((current) =>
                      current.map((c) => (c.id === claim.id ? { ...c, value: event.target.value } : c))
                    )
                  }
                />
                <span
                  className="flex h-9 w-24 shrink-0 items-center justify-center rounded-md border border-line bg-bg font-mono text-xs text-muted"
                  title={`Encoded as ${encodingOf(profile, claim.name)}, as the specification requires for this element`}
                >
                  {LABELS[encodingOf(profile, claim.name)] ?? encodingOf(profile, claim.name)}
                </span>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setClaims((current) => current.filter((c) => c.id !== claim.id))}
                >
                  <Trash2 />
                </Button>
              </div>
            ))}
            <Button
              variant="outline"
              size="sm"
              className="self-start"
              onClick={() =>
                setClaims((current) => [
                  ...current,
                  { id: Math.max(0, ...current.map((c) => c.id)) + 1, name: '', value: '' },
                ])
              }
            >
              <Plus /> Add claim
            </Button>
          </div>

          <div className="flex flex-col gap-1">
            <Label>age_over_NN to derive from birth_date</Label>
            <Input value={ages} onChange={(event) => setAges(event.target.value)} placeholder="18, 21" />
          </div>

          <Button onClick={() => void issue()} disabled={busy}>
            {busy && <Loader2 className="animate-spin" />}
            Issue
          </Button>
        </CardContent>
      </Card>

      <div className="flex flex-col gap-4">
        {error && (
          <Card className="border-bad/40">
            <CardContent className="flex items-start gap-2 text-sm text-bad">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" />
              <span className="break-all">{error}</span>
            </CardContent>
          </Card>
        )}

        {result ? (
          <>
            <Card>
              <CardHeader className="flex-row items-center justify-between">
                <CardTitle>IssuerSigned</CardTitle>
                <div className="flex items-center gap-2">
                  <Badge tone="good">base64url</Badge>
                  <CopyButton value={result.encoded} />
                </div>
              </CardHeader>
              <CardContent>
                <pre className="max-h-64 overflow-auto rounded-md border border-line bg-bg p-3 font-mono text-xs break-all whitespace-pre-wrap">
                  {result.encoded}
                </pre>
                <p className="mt-2 text-xs text-muted">Carried to the Present tab automatically.</p>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Keys and certificate</CardTitle>
                <CardDescription>Generated for this document, in this tab, and never sent anywhere.</CardDescription>
              </CardHeader>
              <CardContent className="py-1">
                <Field label="issuer certificate">
                  <span className="whitespace-pre-wrap">{result.certificatePem.trim()}</span>
                </Field>
                <Field label="device private key">
                  <span className="whitespace-pre-wrap">{result.devicePrivateKeyJwk}</span>
                </Field>
              </CardContent>
            </Card>
          </>
        ) : (
          <Card>
            <CardContent className="text-sm text-muted">
              Fill in the claims and issue a document. The result can be decoded in the Decode tab, or presented in the
              Present tab.
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
