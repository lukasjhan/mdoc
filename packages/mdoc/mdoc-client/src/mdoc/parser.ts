/* eslint-disable @typescript-eslint/no-explicit-any */
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
  DeviceSigned,
  IssuerNameSpaces,
  IssuerSigned,
  RawDeviceAuth,
  RawIndexedDataItem,
  RawIssuerAuth,
  RawNameSpaces,
} from './model/types.js';

const parseIssuerAuthElement = (
  rawIssuerAuth: RawIssuerAuth,
  expectedDocType?: string
): IssuerAuth => {
  const issuerAuth = new IssuerAuth(...rawIssuerAuth);
  const { decodedPayload } = issuerAuth;
  const { docType, version } = decodedPayload;

  if (expectedDocType && docType !== expectedDocType) {
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
 * Parse a IssuerSignedDocument
 *
 * @param issuerSigned - The cbor encoded or decoded IssuerSigned Structure
 * @returns {Promise<IssuerSignedDocument>} - The parsed IssuerSigned document
 */
export const parseIssuerSigned = (
  issuerSigned: Uint8Array | Map<string, any>,
  expectedDocType?: string
): IssuerSignedDocument => {
  let issuerSignedDecoded;
  try {
    issuerSignedDecoded =
      issuerSigned instanceof Map
        ? issuerSigned
        : (cborDecode(issuerSigned) as Map<string, any>);
  } catch (err) {
    throw new MDLParseError(
      `Unable to decode issuer signed document: ${err instanceof Error ? err.message : 'Unknown error'}`
    );
  }

  const issuerAuth = parseIssuerAuthElement(
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    issuerSignedDecoded.get('issuerAuth'),
    expectedDocType
  );

  const parsedIssuerSigned: IssuerSigned = {
    ...issuerSignedDecoded,
    nameSpaces: mapIssuerNameSpaces(
      // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
      issuerSignedDecoded.get('nameSpaces')
    ),
    issuerAuth,
  };

  return new IssuerSignedDocument(
    issuerAuth.decodedPayload.docType,
    parsedIssuerSigned
  );
};

/**
 * Parse a DeviceSignedDocument
 *
 * @param deviceSigned - The cbor encoded or decoded DeviceSigned Structure
 * @param issuerSigned - The cbor encoded or decoded IssuerSigned Structure
 * @returns {Promise<DeviceSignedDocument>} - The parsed DeviceSigned document
 */
export const parseDeviceSigned = (
  deviceSigned: Uint8Array | Map<string, any>,
  issuerSigned: Uint8Array | Map<string, any>,
  expectedDocType?: string
): DeviceSignedDocument => {
  let deviceSignedDecoded;
  try {
    deviceSignedDecoded =
      deviceSigned instanceof Map
        ? deviceSigned
        : (cborDecode(deviceSigned) as Map<string, any>);
  } catch (err) {
    throw new MDLParseError(
      `Unable to decode device signed document : ${err instanceof Error ? err.message : 'Unknown error'}`
    );
  }

  const deviceSignedParsed: DeviceSigned = {
    ...deviceSignedDecoded,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
    nameSpaces: mapDeviceNameSpaces(deviceSignedDecoded.get('nameSpaces').data),
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    deviceAuth: parseDeviceAuthElement(deviceSignedDecoded.get('deviceAuth')),
  };

  const issuerSignedDocument = parseIssuerSigned(issuerSigned, expectedDocType);

  return new DeviceSignedDocument(
    issuerSignedDocument.docType,
    issuerSignedDocument.issuerSigned,
    deviceSignedParsed
  );
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

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const parsedDocuments: IssuerSignedDocument[] = documents.map(
    (doc: Map<string, any>): IssuerSignedDocument => {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const docType = doc.get('docType');
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const issuerSigned = doc.get('issuerSigned');
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const deviceSigned = doc.get('deviceSigned');

      if (deviceSigned) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return parseDeviceSigned(deviceSigned, issuerSigned, docType);
      } else {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return parseIssuerSigned(issuerSigned, docType);
      }
    }
  );

  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  return new MDoc(parsedDocuments, version, status);
};
