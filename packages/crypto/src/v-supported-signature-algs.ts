import * as v from 'valibot';

export namespace SupportedAlgs {
  export const vAsymmetric = v.picklist([
    'PS256',
    'PS384',
    'PS512',
    'RS256',
    'RS384',
    'RS512',
    'ES256',
    'ES384',
    'ES512',
  ]);
  export type Asymetric = v.InferOutput<typeof vAsymmetric>;

  export const vSymmetric = v.picklist(['HS256', 'HS384', 'HS512']);
  export type Symetric = v.InferOutput<typeof vSymmetric>;

  export const vAll = v.picklist([
    ...vAsymmetric.options,
    ...vSymmetric.options,
  ]);
}

export type SupportedAlgs = v.InferOutput<typeof SupportedAlgs.vAll>;
