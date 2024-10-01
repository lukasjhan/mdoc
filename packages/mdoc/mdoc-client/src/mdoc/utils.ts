import { DataItem } from '../cbor/data-item.js';
import { cborDecode, cborEncode } from '../cbor/index.js';

export const calculateDeviceAutenticationBytes = (
  sessionTranscript: Uint8Array | any,
  docType: string,
  nameSpaces: Record<string, Record<string, any>>
): Uint8Array => {
  let decodedSessionTranscript: any;
  if (sessionTranscript instanceof Uint8Array) {
    // assume is encoded in a DataItem
    decodedSessionTranscript = (cborDecode(sessionTranscript) as DataItem).data;
  } else {
    decodedSessionTranscript = sessionTranscript;
  }

  const nameSpacesAsMap = new Map(
    Object.entries(nameSpaces).map(([ns, items]) => [
      ns,
      new Map(Object.entries(items)),
    ])
  );
  const encode = DataItem.fromData([
    'DeviceAuthentication',
    decodedSessionTranscript,
    docType,
    DataItem.fromData(nameSpacesAsMap),
  ]);

  const result = cborEncode(encode);

  return result;
};

// todo
export function fromPEM(pem: string): Uint8Array {
  const base64 = pem
    .replace(/-{5}(BEGIN|END) .*-{5}/gm, '')
    .replace(/\s/gm, '');
  return Buffer.from(base64, 'base64');
}
