import { X509Certificate } from '@peculiar/x509';
import type {
  DeviceSignedDocument,
  IssuerSignedDocument,
} from '@protokoll/mdoc-client';
import {
  COSEKey,
  Document,
  MDoc,
  Verifier,
  defaultCallback,
  parseDeviceResponse,
} from '@protokoll/mdoc-client';
import type { JWK } from 'jose';
import { mdocContext } from '../../src/index.js';
import {
  DEVICE_JWK,
  ISSUER_CERTIFICATE,
  ISSUER_PRIVATE_KEY_JWK,
} from './config.js';

const { d, ...publicKeyJWK } = DEVICE_JWK as JWK;

describe('issuing an MDOC', () => {
  let encodedDeviceResponse: Uint8Array;
  let parsedDocument: IssuerSignedDocument;

  beforeAll(async () => {
    const issuerPrivateKey = ISSUER_PRIVATE_KEY_JWK;

    const document = await new Document('org.iso.18013.5.1.mDL', mdocContext)
      .addIssuerNameSpace('org.iso.18013.5.1', {
        family_name: 'Jones',
        given_name: 'Ava',
        birth_date: '2007-03-25',
      })
      .useDigestAlgorithm('SHA-512')
      .addValidityInfo({
        signed: new Date('2023-10-24'),
        validUntil: new Date('2050-10-24'),
      })
      .addDeviceKeyInfo({ deviceKey: publicKeyJWK })
      .sign(
        {
          issuerPrivateKey,
          issuerCertificate: ISSUER_CERTIFICATE,
          alg: 'ES256',
        },
        mdocContext
      );

    const mdoc = new MDoc([document]);
    encodedDeviceResponse = mdoc.encode();

    const parsedMDOC = parseDeviceResponse(encodedDeviceResponse);
    parsedDocument = parsedMDOC.documents[0] as DeviceSignedDocument;
  });

  it('should be verifiable', async () => {
    const verifier = new Verifier();
    await verifier.verifyDeviceResponse(
      {
        trustedCertificates: [
          new Uint8Array(new X509Certificate(ISSUER_CERTIFICATE).rawData),
        ],
        encodedDeviceResponse,
        onCheck: verification => {
          if (verification.category === 'DEVICE_AUTH') {
            return;
          }
          defaultCallback(verification);
        },
      },
      mdocContext
    );
  });

  it('should contain the validity info', () => {
    const { validityInfo } =
      parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(validityInfo).toBeDefined();
    expect(validityInfo.signed).toEqual(new Date('2023-10-24'));
    expect(validityInfo.validFrom).toEqual(new Date('2023-10-24'));
    expect(validityInfo.validUntil).toEqual(new Date('2050-10-24'));
  });

  it('should use the correct digest alg', () => {
    const { digestAlgorithm } =
      parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(digestAlgorithm).toEqual('SHA-512');
  });

  it('should include the device public key', () => {
    const { deviceKeyInfo } =
      parsedDocument.issuerSigned.issuerAuth.decodedPayload;
    expect(deviceKeyInfo?.deviceKey).toBeDefined();
    const actual =
      typeof deviceKeyInfo !== 'undefined' &&
      COSEKey.import(deviceKeyInfo.deviceKey).toJWK();
    expect(actual).toEqual(publicKeyJWK);
  });

  it('should include the namespace and attributes', () => {
    const attrValues = parsedDocument.getIssuerNameSpace('org.iso.18013.5.1');
    // @ts-expect error this will work
    const currentAge =
      new Date(Date.now() - new Date('2007-03-25').getTime()).getFullYear() -
      1970;
    expect(attrValues).toMatchInlineSnapshot(`
{
  "age_over_${currentAge}": true,
  "age_over_21": ${currentAge >= 21},
  "birth_date": "2007-03-25",
  "family_name": "Jones",
  "given_name": "Ava",
}
`);
  });
});
