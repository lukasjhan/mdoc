import { compareVersions } from 'compare-versions';
import { cborDecode } from '../cbor/index.js';
import { Mac0 } from '../cose/mac0.js';
import { Sign1 } from '../cose/sign1.js';
import { MDLParseError } from './errors.js';
import { IssuerSignedItem } from './issuer-signed-item.js';
import { DeviceSignedDocument } from './model/device-signed-document.js';
import IssuerAuth from './model/issuer-auth.js';
import { IssuerSignedDocument } from './model/issuer-signed-document.js';
import { MDoc } from './model/mdoc.js';
import type {
  DeviceAuth,
  IssuerNameSpaces,
  RawDeviceAuth,
  RawIndexedDataItem,
  RawIssuerAuth,
  RawNameSpaces,
} from './model/types.js';

const parseIssuerAuthElement = (
  rawIssuerAuth: RawIssuerAuth,
  expectedDocType: string
): IssuerAuth => {
  const issuerAuth = new IssuerAuth(...rawIssuerAuth);
  const { decodedPayload } = issuerAuth;
  const { docType, version } = decodedPayload;

  if (docType !== expectedDocType) {
    throw new MDLParseError(
      `The issuerAuth docType must be ${expectedDocType}`
    );
  }

  if (!version || compareVersions(version, '1.0') !== 0) {
    throw new MDLParseError("The issuerAuth version must be '1.0'");
  }

  return issuerAuth;
};

const parseDeviceAuthElement = (rawDeviceAuth: RawDeviceAuth): DeviceAuth => {
  const { deviceSignature, deviceMac } = Object.fromEntries(rawDeviceAuth);
  if (deviceSignature) {
    return { deviceSignature: new Sign1(...deviceSignature) };
  } else if (deviceMac) {
    return { deviceMac: new Mac0(...deviceMac) };
  }

  throw new MDLParseError(
    `Invalid deviceAuth element. Missing 'deviceSignature' and 'deviceMac'`
  );
};

const namespaceToArray = (entries: RawIndexedDataItem): IssuerSignedItem[] => {
  return entries.map(di => new IssuerSignedItem(di));
};

const mapIssuerNameSpaces = (namespace: RawNameSpaces): IssuerNameSpaces => {
  return Array.from(namespace.entries()).reduce(
    (prev, [nameSpace, entries]) => {
      const mappedNamespace = namespaceToArray(entries);
      return {
        ...prev,
        [nameSpace]: mappedNamespace,
      };
    },
    {}
  );
};

const mapDeviceNameSpaces = (namespace: Map<string, Map<string, any>>) => {
  const entries = Array.from(namespace.entries()).map(([ns, attrs]) => {
    return [ns, Object.fromEntries(attrs.entries())];
  });
  return Object.fromEntries(entries);
};

/**
 * Parse an mdoc
 *
 * @param encoded - The cbor encoded mdoc
 * @returns {Promise<MDoc>} - The parsed device response
 */
export const parse = (encoded: Uint8Array): MDoc => {
  let deviceResponse;
  try {
    deviceResponse = cborDecode(encoded) as Map<string, any>;
  } catch (err) {
    throw new MDLParseError(
      `Unable to decode device response: ${err instanceof Error ? err.message : 'Unknown error'}`
    );
  }

  const { version, documents, status } = Object.fromEntries(deviceResponse);

  const parsedDocuments: IssuerSignedDocument[] = documents.map(
    (doc: Map<string, any>): IssuerSignedDocument => {
      const issuerAuth = parseIssuerAuthElement(
        doc.get('issuerSigned').get('issuerAuth'),
        doc.get('docType')
      );

      const issuerSigned = doc.has('issuerSigned')
        ? {
            ...doc.get('issuerSigned'),
            nameSpaces: mapIssuerNameSpaces(
              doc.get('issuerSigned').get('nameSpaces')
            ),
            issuerAuth,
          }
        : undefined;

      const deviceSigned = doc.has('deviceSigned')
        ? {
            ...doc.get('deviceSigned'),
            nameSpaces: mapDeviceNameSpaces(
              doc.get('deviceSigned').get('nameSpaces').data
            ),
            deviceAuth: parseDeviceAuthElement(
              doc.get('deviceSigned').get('deviceAuth')
            ),
          }
        : undefined;

      if (deviceSigned) {
        return new DeviceSignedDocument(
          doc.get('docType'),
          issuerSigned,
          deviceSigned
        );
      }
      return new IssuerSignedDocument(doc.get('docType'), issuerSigned);
    }
  );

  return new MDoc(parsedDocuments, version, status);
};
