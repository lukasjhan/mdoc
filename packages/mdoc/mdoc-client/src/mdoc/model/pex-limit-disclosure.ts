import type { IssuerSignedItem } from '../issuer-signed-item.js';
import type { IssuerSignedDocument } from './issuer-signed-document.js';
import type { InputDescriptor } from './presentation-definition.js';

export const limitDisclosureToInputDescriptor = (input: {
  mdoc: IssuerSignedDocument;
  inputDescriptor: InputDescriptor;
}) => {
  const { mdoc, inputDescriptor } = input;
  const nameSpaces: Record<string, IssuerSignedItem[]> = {};

  for (const field of inputDescriptor.constraints.fields) {
    const result = prepareDigest(field.path, mdoc);
    if (!result) {
      // TODO: Do we add an entry to DocumentErrors if not found?
      console.log(`No matching field found for '${field.path.join('.')}'`);
      continue;
    }

    const { nameSpace, digest } = result;
    if (!nameSpaces[nameSpace]) nameSpaces[nameSpace] = [];
    nameSpaces[nameSpace].push(digest);
  }

  return nameSpaces;
};

const prepareDigest = (
  paths: string[],
  document: IssuerSignedDocument
): { nameSpace: string; digest: IssuerSignedItem } | null => {
  for (const path of paths) {
    const { nameSpace, elementIdentifier } = parsePath(path);
    const nsAttrs = document.issuerSigned.nameSpaces[nameSpace] ?? [];

    if (elementIdentifier.startsWith('age_over_')) {
      return handleAgeOverNN(elementIdentifier, nameSpace, nsAttrs);
    }

    const digest = nsAttrs.find(d => d.elementIdentifier === elementIdentifier);
    if (digest) {
      return { nameSpace, digest };
    }
  }
  return null;
};

const parsePath = (
  path: string
): {
  nameSpace: string;
  elementIdentifier: string;
} => {
  /**
   * path looks like this: "$['org.iso.18013.5.1']['family_name']"
   * the regex creates two groups with contents between "['" and "']"
   * the second entry in each group contains the result without the "'[" or "']"
   *
   * @example org.iso.18013.5.1 family_name
   */
  const matches = [...path.matchAll(/\['(.*?)'\]/g)];
  if (matches.length !== 2) {
    throw new Error(`Invalid path format: "${path}"`);
  }

  const [nameSpaceMatch, elementIdentifierMatch] = matches;
  const nameSpace = nameSpaceMatch?.[1];
  const elementIdentifier = elementIdentifierMatch?.[1];

  if (!nameSpace || !elementIdentifier) {
    throw new Error(`Failed to parse path: "${path}"`);
  }

  return { nameSpace, elementIdentifier };
};

const handleAgeOverNN = (
  request: string,
  nameSpace: string,
  attributes: IssuerSignedItem[]
): { nameSpace: string; digest: IssuerSignedItem } | null => {
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
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    digest: attributes[item.index]!,
  };
};
