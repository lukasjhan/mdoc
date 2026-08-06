import { z } from 'zod'
import {
  buildStructure,
  type CborDecodeOptions,
  CborStructure,
  cborMap,
  cborStructure,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import type { MdocContext } from '../../context'
import { type CoseKey, Header, ProtectedHeaders, UnprotectedHeaders } from '../../cose'
import { base64url } from '../../utils'
import { findIssuerSigned } from '../../utils/findIssuerSigned'
import { limitDisclosureToDeviceRequestNameSpaces } from '../../utils/limitDisclosure'
import { verifyDocRequestsWithIssuerSigned } from '../../utils/verifyDocRequestsWithIssuerSigned'
import { defaultVerificationCallback, type VerificationCallback } from '../check-callback'
import { EitherSignatureOrMacMustBeProvidedError } from '../errors'
import { DeviceAuth, type DeviceAuthOptions } from './device-auth'
import { DeviceAuthentication } from './device-authentication'
import { DeviceMac } from './device-mac'
import { DeviceNamespaces } from './device-namespaces'
import type { DeviceRequest } from './device-request'
import { DeviceSignature } from './device-signature'
import { DeviceSigned } from './device-signed'
import { Document, type DocumentStructure } from './document'
import { DocumentError, type DocumentErrorStructure } from './document-error'
import { IssuerSigned } from './issuer-signed'
import type { SessionTranscript } from './session-transcript'

const schema = cborMap([
  ['version', z.string()],
  ['documents', z.array(cborStructure(Document)).optional()],
  ['documentErrors', z.array(cborStructure(DocumentError)).optional()],
  ['status', z.number()],
])

export type DeviceResponseStructure = {
  version: string
  documents?: Array<DocumentStructure>
  documentErrors?: Array<DocumentErrorStructure>
  status: number
}

export type DeviceResponseOptions = {
  version?: string
  documents?: Array<Document>
  documentErrors?: Array<DocumentError>
  status?: number
}

export class DeviceResponse extends CborStructure {
  public static override schema = schema

  public constructor(options: DeviceResponseOptions) {
    super(
      buildStructure([
        ['version', options.version ?? '1.0'],
        ['documents', options.documents],
        ['documentErrors', options.documentErrors],
        ['status', options.status ?? 0],
      ])
    )
  }

  public get version(): string {
    return this.structure.get('version') as string
  }

  public get documents(): Array<Document> | undefined {
    return this.structure.get('documents') as Array<Document> | undefined
  }

  public get documentErrors(): Array<DocumentError> | undefined {
    return this.structure.get('documentErrors') as Array<DocumentError> | undefined
  }

  public get status(): number {
    return this.structure.get('status') as number
  }

  public override encodedStructure(): DeviceResponseStructure {
    return super.encodedStructure() as DeviceResponseStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): DeviceResponse {
    return fromEncoded(DeviceResponse, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceResponse {
    return decodeBytes(DeviceResponse, bytes, options)
  }

  public async verify(
    options: {
      deviceRequest?: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      ephemeralReaderKey?: CoseKey
      disableCertificateChainValidation?: boolean
      trustedCertificates: Uint8Array[]
      now?: Date
      onCheck?: VerificationCallback
      skewSeconds?: number
    },
    ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto'>
  ) {
    const onCheck = options.onCheck ?? defaultVerificationCallback

    onCheck({
      status: this.version ? 'PASSED' : 'FAILED',
      check: 'Device Response must include "version" element.',
      category: 'DOCUMENT_FORMAT',
    })

    onCheck({
      status: !this.documents || (this.documents && this.documents.length > 0) ? 'PASSED' : 'FAILED',
      check: 'Device Response must not include documents or at least one document.',
      category: 'DOCUMENT_FORMAT',
    })

    for (const document of this.documents ?? []) {
      await Promise.all([
        document.issuerSigned.issuerAuth.verify(
          {
            disableCertificateChainValidation: options.disableCertificateChainValidation,
            now: options.now,
            trustedCertificates: options.trustedCertificates,
            verificationCallback: onCheck,
            skewSeconds: options.skewSeconds,
          },
          ctx
        ),

        document.deviceSigned.deviceAuth.verify(
          {
            document,
            ephemeralMacPrivateKey: options.ephemeralReaderKey,
            sessionTranscript: options.sessionTranscript,
            verificationCallback: onCheck,
          },
          ctx
        ),

        document.issuerSigned.verify({ verificationCallback: onCheck }, ctx),
      ])
    }

    if (options.deviceRequest?.docRequests && this.documents) {
      try {
        verifyDocRequestsWithIssuerSigned(
          options.deviceRequest.docRequests,
          this.documents.map((d) => d.issuerSigned)
        )
        onCheck({
          status: 'PASSED',
          check: 'Device Response did match the Device Request',
          category: 'DOCUMENT_FORMAT',
        })
      } catch (e) {
        onCheck({
          status: 'FAILED',
          check: `Device Response did not match the Device Request: ${(e as Error).message}`,
          category: 'DOCUMENT_FORMAT',
        })
      }
    }
  }

  public get encodedForOid4Vp() {
    return base64url.encode(this.encode())
  }

  public static fromEncodedForOid4Vp(encoded: string): DeviceResponse {
    return DeviceResponse.decode(base64url.decode(encoded))
  }

  private static async create(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: Array<IssuerSigned>
      deviceNamespaces?: DeviceNamespaces
      signature?: {
        signingKey: CoseKey
      }
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    const useMac = !!options.mac
    const useSignature = !!options.signature
    if (useMac === useSignature) throw new EitherSignatureOrMacMustBeProvidedError()

    const signingKey = useSignature ? options.signature?.signingKey : options.mac?.signingKey
    if (!signingKey) throw new Error('Signing key is missing')

    const documents = await Promise.all(
      options.deviceRequest.docRequests.map(async (docRequest) => {
        const issuerSigned = findIssuerSigned(options.issuerSigned, docRequest.itemsRequest.docType)
        const disclosedIssuerNamespace = limitDisclosureToDeviceRequestNameSpaces(issuerSigned, docRequest)

        const docType = docRequest.itemsRequest.docType

        const deviceNamespaces = options.deviceNamespaces ?? new DeviceNamespaces({ deviceNamespaces: new Map() })

        const deviceAuthenticationBytes = new DeviceAuthentication({
          sessionTranscript: options.sessionTranscript,
          docType,
          deviceNamespaces,
        }).encode({ asDataItem: true })

        const unprotectedHeaders = signingKey.keyId
          ? new UnprotectedHeaders({ unprotectedHeaders: new Map([[Header.KeyId, signingKey.keyId]]) })
          : new UnprotectedHeaders({})

        const protectedHeaders = new ProtectedHeaders({
          protectedHeaders: new Map([[Header.Algorithm, signingKey.algorithm]]),
        })

        const deviceAuthOptions: DeviceAuthOptions = {}
        if (useSignature) {
          deviceAuthOptions.deviceSignature = await new DeviceSignature({
            unprotectedHeaders,
            protectedHeaders,
            detachedContent: deviceAuthenticationBytes,
          }).sign({ signingKey }, ctx)
        } else {
          const ephemeralKey = options.mac?.ephemeralKey
          if (!ephemeralKey) throw new Error('Ephemeral key is missing')

          deviceAuthOptions.deviceMac = await new DeviceMac({
            protectedHeaders,
            unprotectedHeaders,
            detachedContent: deviceAuthenticationBytes,
          }).authenticate(
            {
              privateKey: signingKey,
              ephemeralKey: ephemeralKey,
              sessionTranscript: options.sessionTranscript,
            },
            ctx
          )
        }

        return new Document({
          docType,
          issuerSigned: new IssuerSigned({
            issuerNamespaces: disclosedIssuerNamespace,
            issuerAuth: issuerSigned.issuerAuth,
          }),
          deviceSigned: new DeviceSigned({
            deviceNamespaces,
            deviceAuth: new DeviceAuth(deviceAuthOptions),
          }),
        })
      })
    )

    return new DeviceResponse({
      documents,
    })
  }

  public static async createWithDeviceRequest(
    options: {
      deviceRequest: DeviceRequest
      sessionTranscript: SessionTranscript | Uint8Array
      issuerSigned: Array<IssuerSigned>
      deviceNamespaces?: DeviceNamespaces
      mac?: {
        ephemeralKey: CoseKey
        signingKey: CoseKey
      }
      signature?: {
        signingKey: CoseKey
      }
    },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ) {
    return await DeviceResponse.create(options, ctx)
  }
}
