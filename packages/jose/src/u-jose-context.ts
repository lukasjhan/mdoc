import * as jose from 'jose';
import type { JoseContext, JoseJwkCalculateThumbprintUri } from './index.js';
import type {
  JoseJweDecryptCompact,
  JoseJweDecryptJwt,
  JoseJweEncryptCompact,
  JoseJweEncryptJwt,
} from './jwe/c-jwe.js';
import type {
  JoseJwsSignCompact,
  JoseJwsSignJwt,
  JoseJwsVerifyCompact,
  JoseJwsVerifyJwt,
} from './jws/c-jws.js';

const decryptJwt: JoseJweDecryptJwt = async input => {
  const { jwe, jwk } = input;
  const privateKey = await jose.importJWK(jwk);

  return await jose.jwtDecrypt(jwe, privateKey);
};

const decryptCompact: JoseJweDecryptCompact = async input => {
  const { jwe, jwk } = input;
  const privateKey = await jose.importJWK(jwk);
  const decode = TextDecoder.prototype.decode.bind(new TextDecoder());

  const { plaintext, protectedHeader } = await jose.compactDecrypt(
    jwe,
    privateKey
  );

  return {
    plaintext: decode(plaintext),
    protectedHeader,
  };
};

const encryptJwt: JoseJweEncryptJwt = async input => {
  const { payload, protectedHeader, jwk, alg, keyManagement } = input;
  const encode = TextEncoder.prototype.encode.bind(new TextEncoder());
  const recipientPublicKey = await jose.importJWK(jwk, alg);

  const joseEncryptJwt = new jose.EncryptJWT(payload).setProtectedHeader(
    protectedHeader
  );

  if (keyManagement) {
    joseEncryptJwt.setKeyManagementParameters({
      apu: encode(keyManagement.apu),
      apv: encode(keyManagement.apv),
    });
  }

  const jwe = await joseEncryptJwt.encrypt(recipientPublicKey);
  return { jwe };
};

const encryptCompact: JoseJweEncryptCompact = async input => {
  const { plaintext, protectedHeader, jwk, alg, keyManagement } = input;
  const encode = TextEncoder.prototype.encode.bind(new TextEncoder());
  const recipientPublicKey = await jose.importJWK(jwk, alg);

  const joseEncryptJwt = new jose.CompactEncrypt(
    encode(plaintext)
  ).setProtectedHeader(protectedHeader);

  if (keyManagement) {
    joseEncryptJwt.setKeyManagementParameters({
      apu: encode(keyManagement.apu),
      apv: encode(keyManagement.apv),
    });
  }

  const jwe = await joseEncryptJwt.encrypt(recipientPublicKey);
  return { jwe: jwe };
};

const signJwt: JoseJwsSignJwt = async input => {
  const { payload, protectedHeader, jwk } = input;
  const privateKey = await jose.importJWK(jwk);

  const jws = await new jose.SignJWT(payload)
    .setProtectedHeader(protectedHeader)
    .sign(privateKey);

  return { jws };
};

const signCompact: JoseJwsSignCompact = async input => {
  const { payload, protectedHeader, jwk } = input;
  const privateKey = await jose.importJWK(jwk);
  const encode = TextEncoder.prototype.encode.bind(new TextEncoder());

  const jws = await new jose.CompactSign(encode(payload))
    .setProtectedHeader(protectedHeader)
    .sign(privateKey);

  return { jws };
};

const verifyJwt: JoseJwsVerifyJwt = async input => {
  const { jwk, jws, options } = input;
  const privateKey = await jose.importJWK(jwk);
  return await jose.jwtVerify(jws, privateKey, options);
};

const verifyCompact: JoseJwsVerifyCompact = async input => {
  const { jwk, jws, options } = input;
  const privateKey = await jose.importJWK(jwk);
  const decode = TextDecoder.prototype.decode.bind(new TextDecoder());

  const res = await jose.compactVerify(jws, privateKey, options);
  return { payload: decode(res.payload), protectedHeader: res.protectedHeader };
};

const calculateThumbprintUri: JoseJwkCalculateThumbprintUri = async input => {
  const { jwk, digestAlgorithm } = input;

  const jwkThumbprintUri = await jose.calculateJwkThumbprintUri(
    jwk,
    digestAlgorithm
  );

  return { jwkThumbprintUri };
};

export const joseContext: JoseContext = {
  jose: {
    jwe: {
      decryptCompact,
      decryptJwt,
      encryptCompact,
      encryptJwt,
    },
    jws: {
      signJwt,
      verifyJwt,
      signCompact,
      verifyCompact,
    },
    jwk: {
      calculateThumbprintUri,
    },
  },
};
