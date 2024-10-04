import { stringToUint8Array } from '@protokoll/core';
import type { JWK } from 'jose';
import type { MdocContext } from '../../c-mdoc.js';
import { DataItem, cborEncode } from '../../cbor/index.js';
import {
  Algorithms,
  Headers,
  MacAlgorithms,
  MacProtectedHeaders,
  ProtectedHeaders,
  UnprotectedHeaders,
} from '../../cose/headers.js';
import { COSEKey, COSEKeyToRAW } from '../../cose/key/cose-key.js';
import { Mac0 } from '../../cose/mac0.js';
import { Sign1 } from '../../cose/sign1.js';
import type { IssuerSignedItem } from '../issuer-signed-item.js';
import { parse } from '../parser.js';
import { calculateDeviceAutenticationBytes } from '../utils.js';
import { DeviceSignedDocument } from './device-signed-document.js';
import type { IssuerSignedDocument } from './issuer-signed-document.js';
import { MDoc } from './mdoc.js';
import type {
  InputDescriptor,
  PresentationDefinition,
} from './presentation-definition.js';
import type {
  DeviceAuth,
  DeviceSigned,
  MacSupportedAlgs,
  SupportedAlgs,
} from './types.js';

/**
 * A builder class for creating a device response.
 */
export class DeviceResponse {
  private mdoc: MDoc;
  private pd?: PresentationDefinition;
  private sessionTranscriptBytes?: Uint8Array;
  private useMac = true;
  private devicePrivateKey?: Uint8Array;
  public deviceResponseCbor?: Uint8Array;
  public nameSpaces: Record<string, Record<string, any>> = {};
  private alg?: SupportedAlgs;
  private macAlg?: MacSupportedAlgs;
  private ephemeralPublicKey?: Uint8Array;

  /**
   * Create a DeviceResponse builder.
   *
   * @param {MDoc | Uint8Array} mdoc - The mdoc to use as a base for the device response.
   *                                   It can be either a parsed MDoc or a CBOR encoded MDoc.
   * @returns {DeviceResponse} - A DeviceResponse builder.
   */
  public static from(mdoc: MDoc | Uint8Array): DeviceResponse {
    if (mdoc instanceof Uint8Array) {
      return new DeviceResponse(parse(mdoc));
    }
    return new DeviceResponse(mdoc);
  }

  constructor(mdoc: MDoc) {
    this.mdoc = mdoc;
  }

  /**
   *
   * @param pd - The presentation definition to use for the device response.
   * @returns {DeviceResponse}
   */
  public usingPresentationDefinition(
    pd: PresentationDefinition
  ): DeviceResponse {
    if (!pd.input_descriptors.length) {
      throw new Error(
        'The Presentation Definition must have at least one Input Descriptor object.'
      );
    }

    const hasDuplicates = pd.input_descriptors.some(
      (id1, idx) =>
        pd.input_descriptors.findIndex(id2 => id2.id === id1.id) !== idx
    );
    if (hasDuplicates) {
      throw new Error(
        'Each Input Descriptor object must have a unique id property.'
      );
    }

    this.pd = pd;
    return this;
  }

  /**
   * Set the session transcript data to use for the device response.
   *
   * This is arbitrary and should match the session transcript as it will be calculated by the verifier.
   * The transcript must be a CBOR encoded DataItem of an array, there is no further requirement.
   *
   * Example: `usingSessionTranscriptBytes(cborEncode(DataItem.fromData([a,b,c])))` where `a`, `b` and `c` can be anything including `null`.
   *
   * It is preferable to use {@link usingSessionTranscriptForOID4VP} or {@link usingSessionTranscriptForWebAPI} when possible.
   *
   * @param {Uint8Array} sessionTranscriptBytes - The sessionTranscriptBytes data to use in the session transcript.
   * @returns {DeviceResponse}
   */
  public usingSessionTranscriptBytes(
    sessionTranscriptBytes: Uint8Array
  ): DeviceResponse {
    if (this.sessionTranscriptBytes) {
      throw new Error(
        'A session transcript has already been set, either with .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes'
      );
    }
    this.sessionTranscriptBytes = sessionTranscriptBytes;
    return this;
  }

  /**
   * Set the session transcript data to use for the device response as defined in ISO/IEC 18013-7 in Annex B (OID4VP), 2023 draft.
   *
   * This should match the session transcript as it will be calculated by the verifier.
   *
   * @param {string} mdocGeneratedNonce - A cryptographically random number with sufficient entropy.
   * @param {string} clientId - The client_id Authorization Request parameter from the Authorization Request Object.
   * @param {string} responseUri - The response_uri Authorization Request parameter from the Authorization Request Object.
   * @param {string} verifierGeneratedNonce - The nonce Authorization Request parameter from the Authorization Request Object.
   * @returns {DeviceResponse}
   */
  public usingSessionTranscriptForOID4VP(
    mdocGeneratedNonce: string,
    clientId: string,
    responseUri: string,
    verifierGeneratedNonce: string
  ): DeviceResponse {
    this.usingSessionTranscriptBytes(
      cborEncode(
        DataItem.fromData([
          null, // deviceEngagementBytes
          null, // eReaderKeyBytes
          [mdocGeneratedNonce, clientId, responseUri, verifierGeneratedNonce],
        ])
      )
    );
    return this;
  }
  /**
   * Set the session transcript data to use for the device response as defined in ISO/IEC 18013-7 in Annex A (Web API), 2023 draft.
   *
   * This should match the session transcript as it will be calculated by the verifier.
   *
   * @param {Uint8Array} deviceEngagementBytes - The device engagement, encoded as a Tagged 24 cbor
   * @param {Uint8Array} readerEngagementBytes - The reader engagement, encoded as a Tagged 24 cbor
   * @param {Uint8Array} eReaderKeyBytes - The reader ephemeral public key as a COSE Key, encoded as a Tagged 24 cbor
   * @returns {DeviceResponse}
   */
  public usingSessionTranscriptForWebAPI(
    deviceEngagementBytes: Uint8Array,
    readerEngagementBytes: Uint8Array,
    eReaderKeyBytes: Uint8Array
  ): DeviceResponse {
    this.usingSessionTranscriptBytes(
      cborEncode(
        DataItem.fromData([
          new DataItem({ buffer: deviceEngagementBytes }),
          new DataItem({ buffer: eReaderKeyBytes }),
          readerEngagementBytes,
        ])
      )
    );
    return this;
  }

  /**
   * Add a namespace to the device response.
   *
   * @param {string} nameSpace - The name space to add to the device response.
   * @param {Record<string, any>} data - The data to add to the name space.
   * @returns {DeviceResponse}
   */
  public addDeviceNameSpace(
    nameSpace: string,
    data: Record<string, any>
  ): DeviceResponse {
    this.nameSpaces[nameSpace] = data;
    return this;
  }

  /**
   * Set the device's private key to be used for signing the device response.
   *
   * @param  {JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
   * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
   * @returns {DeviceResponse}
   */
  public authenticateWithSignature(
    devicePrivateKey: JWK | Uint8Array,
    alg: SupportedAlgs
  ): DeviceResponse {
    if (devicePrivateKey instanceof Uint8Array) {
      this.devicePrivateKey = devicePrivateKey;
    } else {
      this.devicePrivateKey = COSEKey.fromJWK(devicePrivateKey).encode();
    }
    this.alg = alg;
    this.useMac = false;
    return this;
  }

  /**
   * Set the reader shared key to be used for signing the device response with MAC.
   *
   * @param  {JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
   * @param  {Uint8Array} ephemeralPublicKey - The public part of the ephemeral key generated by the MDOC.
   * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
   * @returns {DeviceResponse}
   */
  public authenticateWithMAC(
    devicePrivateKey: JWK | Uint8Array,
    ephemeralPublicKey: Uint8Array,
    alg: MacSupportedAlgs
  ): DeviceResponse {
    if (devicePrivateKey instanceof Uint8Array) {
      this.devicePrivateKey = devicePrivateKey;
    } else {
      this.devicePrivateKey = COSEKey.fromJWK(devicePrivateKey).encode();
    }
    this.ephemeralPublicKey = ephemeralPublicKey;
    this.macAlg = alg;
    this.useMac = true;
    return this;
  }

  /**
   * Sign the device response and return the MDoc.
   *
   * @returns {Promise<MDoc>} - The device response as an MDoc.
   */
  public async sign(ctx: {
    crypto: MdocContext['crypto'];
    cose: MdocContext['cose'];
  }): Promise<MDoc> {
    if (!this.pd) {
      throw new Error(
        'Must provide a presentation definition with .usingPresentationDefinition()'
      );
    }

    if (!this.sessionTranscriptBytes) {
      throw new Error(
        'Must provide the session transcript with either .usingSessionTranscriptForOID4VP, .usingSessionTranscriptForWebAPI or .usingSessionTranscriptBytes'
      );
    }

    const docs = await Promise.all(
      this.pd.input_descriptors.map(id => this.handleInputDescriptor(id, ctx))
    );
    return new MDoc(docs);
  }

  private async handleInputDescriptor(
    id: InputDescriptor,
    ctx: {
      cose: MdocContext['cose'];
      crypto: MdocContext['crypto'];
    }
  ): Promise<DeviceSignedDocument> {
    const document = (this.mdoc.documents || []).find(d => d.docType === id.id);
    if (!document) {
      // TODO; probl need to create a DocumentError here, but let's just throw for now
      throw new Error(
        `The mdoc does not have a document with DocType "${id.id}"`
      );
    }

    const nameSpaces = await this.prepareNamespaces(id, document);

    return new DeviceSignedDocument(
      document.docType,
      {
        nameSpaces,
        issuerAuth: document.issuerSigned.issuerAuth,
      },
      await this.getDeviceSigned(document.docType, ctx)
    );
  }

  private async getDeviceSigned(
    docType: string,
    ctx: {
      cose: MdocContext['cose'];
      crypto: MdocContext['crypto'];
    }
  ): Promise<DeviceSigned> {
    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      this.sessionTranscriptBytes,
      docType,
      this.nameSpaces
    );

    const deviceSigned: DeviceSigned = {
      nameSpaces: this.nameSpaces,
      deviceAuth: this.useMac
        ? await this.getDeviceAuthMac(
            deviceAuthenticationBytes,
            this.sessionTranscriptBytes,
            ctx
          )
        : await this.getDeviceAuthSign(deviceAuthenticationBytes, ctx),
    };

    return deviceSigned;
  }

  private async getDeviceAuthMac(
    deviceAuthenticationBytes: Uint8Array,
    sessionTranscriptBytes: any,
    ctx: {
      cose: Pick<MdocContext['cose'], 'mac0'>;
      crypto: MdocContext['crypto'];
    }
  ): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) {
      throw new Error('Missing devicePrivateKey for getDeviceAuthMac');
    }

    if (!this.ephemeralPublicKey) {
      throw new Error('Missing ephemeralPublicKey for getDeviceAuthMac');
    }

    const key = COSEKeyToRAW(this.devicePrivateKey);
    const { kid } = COSEKey.import(this.devicePrivateKey).toJWK();

    const ephemeralMacKeyJwk = await ctx.crypto.calculateEphemeralMacKeyJwk({
      privateKey: key,
      publicKey: this.ephemeralPublicKey,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      sessionTranscriptBytes: sessionTranscriptBytes,
    });

    if (!this.macAlg) throw new Error('Missing macAlg');

    const protectedHeaders = MacProtectedHeaders.from([
      [Headers.Algorithm, MacAlgorithms[this.macAlg]],
    ]);

    const unprotectedHeaders = kid
      ? UnprotectedHeaders.from([[Headers.KeyID, stringToUint8Array(kid)]])
      : undefined;

    const mac0 = Mac0.create(
      protectedHeaders,
      unprotectedHeaders,
      deviceAuthenticationBytes,
      undefined
    );

    const tag = await ctx.cose.mac0.sign({ mac0, jwk: ephemeralMacKeyJwk });
    mac0.tag = tag;
    return { deviceMac: mac0 };
  }

  private async getDeviceAuthSign(
    cborData: Uint8Array,
    ctx: {
      crypto: MdocContext['crypto'];
      cose: MdocContext['cose'];
    }
  ): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) throw new Error('Missing devicePrivateKey');

    if (!this.alg) {
      throw new Error('The alg header must be set.');
    }

    const { kid } = COSEKey.import(this.devicePrivateKey).toJWK();
    const unprotectedHeaders = kid
      ? UnprotectedHeaders.from([[Headers.KeyID, stringToUint8Array(kid)]])
      : undefined;

    const sign1 = Sign1.create(
      ProtectedHeaders.from([[Headers.Algorithm, Algorithms[this.alg]]]),
      unprotectedHeaders,
      cborData
    );

    const jwk = COSEKey.import(this.devicePrivateKey).toJWK();
    const signature = await ctx.cose.sign1.sign({ sign1, jwk });
    sign1.signature = signature;

    return { deviceSignature: sign1 };
  }

  private async prepareNamespaces(
    id: InputDescriptor,
    document: IssuerSignedDocument
  ) {
    const requestedFields = id.constraints.fields;
    const nameSpaces: Record<string, any> = {};
    for await (const field of requestedFields) {
      const result = this.prepareDigest(field.path, document);
      if (!result) {
        // TODO: Do we add an entry to DocumentErrors if not found?
        console.log(`No matching field found for ${field.path}`);
        continue;
      }

      const { nameSpace, digest } = result;
      if (!nameSpaces[nameSpace]) nameSpaces[nameSpace] = [];
      nameSpaces[nameSpace].push(digest);
    }

    return nameSpaces;
  }

  private prepareDigest(
    paths: string[],
    document: IssuerSignedDocument
  ): { nameSpace: string; digest: IssuerSignedItem } | null {
    /**
     * path looks like this: "$['org.iso.18013.5.1']['family_name']"
     * the regex creates two groups with contents between "['" and "']"
     * the second entry in each group contains the result without the "'[" or "']"
     */
    for (const path of paths) {
      // @ts-expect-error this is hacky
      const [[_1, nameSpace], [_2, elementIdentifier]] = [
        ...path.matchAll(/\['(.*?)'\]/g),
      ];
      if (!nameSpace)
        throw new Error(`Failed to parse namespace from path "${path}"`);
      if (!elementIdentifier)
        throw new Error(
          `Failed to parse elementIdentifier from path "${path}"`
        );

      const nsAttrs: IssuerSignedItem[] =
        document.issuerSigned.nameSpaces[nameSpace] ?? [];
      const digest = nsAttrs.find(
        d => d.elementIdentifier === elementIdentifier
      );

      if (elementIdentifier.startsWith('age_over_')) {
        return this.handleAgeOverNN(elementIdentifier, nameSpace, nsAttrs);
      }

      if (digest) {
        return {
          nameSpace,
          digest,
        };
      }
    }

    return null;
  }

  private handleAgeOverNN(
    request: string,
    nameSpace: string,
    attributes: IssuerSignedItem[]
  ): { nameSpace: string; digest: IssuerSignedItem } | null {
    const ageOverList = attributes
      .map((a, i) => {
        const { elementIdentifier: key, elementValue: value } = a;
        return { key, value, index: i };
      })
      .filter(i => i.key.startsWith('age_over_'))
      .map(i => ({
        nn: parseInt(i.key.replace('age_over_', ''), 10),
        ...i,
      }))
      .sort((a, b) => a.nn - b.nn);

    const reqNN = parseInt(request.replace('age_over_', ''), 10);

    let item;
    // Find nearest TRUE
    item = ageOverList.find(i => i.value === true && i.nn >= reqNN);

    if (!item) {
      // Find the nearest False
      item = ageOverList
        .sort((a, b) => b.nn - a.nn)
        .find(i => i.value === false && i.nn <= reqNN);
    }

    if (!item) {
      return null;
    }

    return {
      nameSpace,
      digest: attributes[item.index]!,
    };
  }
}
