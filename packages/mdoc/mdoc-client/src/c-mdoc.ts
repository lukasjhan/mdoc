import type { JWK } from 'jose';
import type {
  MacProtectedHeaders,
  ProtectedHeaders,
  UnprotectedHeaders,
} from './cose/headers.js';
import type { VerifyOptions as Mac0VerifyOpts } from './cose/mac0.js';
import type { VerifyOptions as Sign1VerifyOpts } from './cose/signature-base.js';
import type { DigestAlgorithm } from './mdoc/model/types.js';

export type MaybePromise<TType> = Promise<TType> | TType;

export interface X509Context {
  getIssuerName: (input: {
    certificate: Uint8Array;
  }) => NonNullable<unknown> | undefined;
  getIssuerNameField: (input: {
    certificate: Uint8Array;
    field: string;
  }) => string[];
  getPublicKey: (input: {
    certificate: Uint8Array;
    alg: string;
  }) => MaybePromise<Uint8Array>;
  validateCertificateChain: (input: {
    certificates: [string, ...string[]];
  }) => MaybePromise<void>;
  getCertificateData: (input: { certificate: Uint8Array }) => MaybePromise<{
    subjectName: string;
    pem: string;
    serialNumber: string;
    thumbprint: string;
  }>;
  getCertificateValidityData: (input: {
    certificate: Uint8Array;
  }) => MaybePromise<{
    notBefore: Date;
    notAfter: Date;
  }>;
}

export interface MdocContext {
  crypto: {
    random: (length: number) => Promise<Uint8Array>;
    digest: (input: {
      digestAlgorithm: DigestAlgorithm;
      bytes: Uint8Array;
    }) => MaybePromise<Uint8Array>;
    /**
     * Calculates the ephemeral mac key for the device authentication.
     *
     * There are two cases for this function:
     * 1. SDeviceKey.Priv and EReaderKey.Pub for the mdoc
     * 2. EReaderKey.Priv and SDeviceKey.Pub for the mdoc reader
     *
     * @param {Uint8Array} privateKey - The private key of the current party
     * @param {Uint8Array} publicKey - The public key of the other party
     * @param {Uint8Array} sessionTranscriptBytes - The session transcript bytes
     * @returns {Uint8Array} - The ephemeral mac key
     */
    calculateEphemeralMacKey: (input: {
      privateKey: Uint8Array;
      publicKey: Uint8Array;
      sessionTranscriptBytes: Uint8Array;
    }) => MaybePromise<Uint8Array>;
  };
  jose: {
    importJwk: (jwk: JWK) => Promise<Uint8Array>;
  };
  cose: {
    sign1: {
      sign: (input: {
        protectedHeaders:
          | ProtectedHeaders
          | ConstructorParameters<typeof ProtectedHeaders>[0];
        unprotectedHeaders:
          | UnprotectedHeaders
          | ConstructorParameters<typeof UnprotectedHeaders>[0]
          | undefined;
        payload: Uint8Array;
        key: Uint8Array;
      }) => MaybePromise<Uint8Array>;

      verify(input: {
        key: Uint8Array;
        options: Sign1VerifyOpts | undefined;
        protectedHeaders: Map<number, unknown>;
        unprotectedHeaders: Map<number, unknown>;
        payload: Uint8Array;
        signature: Uint8Array;
      }): MaybePromise<boolean>;
    };

    mac0: {
      sign: (input: {
        protectedHeaders:
          | MacProtectedHeaders
          | ConstructorParameters<typeof MacProtectedHeaders>[0];
        unprotectedHeaders:
          | UnprotectedHeaders
          | ConstructorParameters<typeof UnprotectedHeaders>[0]
          | undefined;
        payload: Uint8Array;
        key: Uint8Array;
      }) => MaybePromise<Uint8Array>;

      verify(input: {
        key: Uint8Array;
        options: Mac0VerifyOpts | undefined;
        protectedHeaders: Map<number, unknown>;
        unprotectedHeaders: Map<number, unknown>;
        payload: Uint8Array;
        tag: Uint8Array;
      }): MaybePromise<boolean>;
    };
  };

  x509: X509Context;
}
