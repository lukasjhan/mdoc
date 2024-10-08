import { p256 } from '@noble/curves/p256';
import * as x509 from '@peculiar/x509';
import { X509Certificate } from '@peculiar/x509';
import {
  stringToUint8Array,
  uint8ArrayToBase64Url,
  uint8ArrayToHex,
} from '@protokoll/core';
import {
  exportJwk,
  hkdf,
  importX509,
  signWithJwk,
  verifyWithJwk,
} from '@protokoll/crypto';
import type { MdocContext, X509Context } from '@protokoll/mdoc-client';
import type { JWK } from 'jose';

export const mdocContext: MdocContext = {
  crypto: {
    digest: async ({ digestAlgorithm, bytes }) => {
      const digest = await crypto.subtle.digest(digestAlgorithm, bytes);
      return new Uint8Array(digest);
    },
    random: (length: number) => {
      return crypto.getRandomValues(new Uint8Array(length));
    },
    calculateEphemeralMacKeyJwk: async input => {
      const { privateKey, publicKey, sessionTranscriptBytes } = input;
      const ikm = p256
        .getSharedSecret(
          uint8ArrayToHex(privateKey),
          uint8ArrayToHex(publicKey),
          true
        )
        .slice(1);
      const salt = new Uint8Array(
        await crypto.subtle.digest('SHA-256', sessionTranscriptBytes)
      );
      const info = stringToUint8Array('EMacKey');
      const digest = 'sha256';
      const result = await hkdf({ digest, ikm, salt, info, keylen: 32 });

      return {
        key_ops: ['sign', 'verify'],
        ext: true,
        kty: 'oct',
        k: uint8ArrayToBase64Url(result),
        alg: 'HS256',
      };
    },
  },

  cose: {
    mac0: {
      sign: async input => {
        const { jwk, mac0 } = input;
        const { data, alg } = mac0.getRawSigningData();
        return await signWithJwk({ jwk, data, alg });
      },
      verify: async input => {
        const { mac0, jwk, options } = input;
        const { data, signature, alg } = mac0.getRawVerificationData(options);
        return verifyWithJwk({ jwk, signature, data, alg });
      },
    },
    sign1: {
      sign: async input => {
        const { jwk, sign1 } = input;
        const { data, alg } = sign1.getRawSigningData();
        return await signWithJwk({ jwk, data, alg });
      },
      verify: async input => {
        const { sign1, jwk, options } = input;
        const { data, signature, alg } = sign1.getRawVerificationData(options);
        return verifyWithJwk({ jwk, signature, data, alg });
      },
    },
  },

  x509: {
    getIssuerNameField: (input: { certificate: Uint8Array; field: string }) => {
      const certificate = new X509Certificate(input.certificate);
      return certificate.issuerName.getField(input.field);
    },
    getPublicKey: async (input: { certificate: Uint8Array; alg: string }) => {
      const certificate = new X509Certificate(input.certificate);
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const key = await importX509({
        x509: certificate.toString(),
        alg: input.alg,
        extractable: true,
      });
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      return (await exportJwk({ key })) as JWK;
    },

    validateCertificateChain: async (input: {
      trustedCertificates: [Uint8Array, ...Uint8Array[]];
      x5chain: [Uint8Array, ...Uint8Array[]];
    }) => {
      const { trustedCertificates, x5chain: certificateChain } = input;
      if (certificateChain.length === 0)
        throw new Error('Certificate chain is empty');

      const parsedLeafCertificate = new x509.X509Certificate(
        certificateChain[0]
      );

      const parsedCertificates = certificateChain.map(
        c => new x509.X509Certificate(c)
      );

      const certificateChainBuilder = new x509.X509ChainBuilder({
        certificates: parsedCertificates,
      });

      const chain = await certificateChainBuilder.build(parsedLeafCertificate);

      // The chain is reversed here as the `x5c` header (the expected input),
      // has the leaf certificate as the first entry, while the `x509` library expects this as the last
      let parsedChain = chain
        .map(c => new x509.X509Certificate(c.rawData))
        .reverse();

      if (parsedChain.length !== certificateChain.length) {
        throw new Error(
          'Could not parse the full chain. Likely due to incorrect ordering'
        );
      }

      const parsedTrustedCertificates = trustedCertificates.map(
        trustedCertificate => new x509.X509Certificate(trustedCertificate)
      );

      const trustedCertificateIndex = parsedChain.findIndex(cert =>
        parsedTrustedCertificates.some(tCert => cert.equal(tCert))
      );

      if (trustedCertificateIndex === -1) {
        throw new Error(
          'No trusted certificate was found while validating the X.509 chain'
        );
      }

      // Pop everything off above the index of the trusted as it is not relevant for validation
      parsedChain = parsedChain.slice(0, trustedCertificateIndex);

      // Verify the certificate with the publicKey of the certificate above
      for (let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i];
        const previousCertificate = parsedChain[i - 1];
        const publicKey = previousCertificate
          ? previousCertificate.publicKey
          : undefined;
        await cert?.verify({ publicKey, date: new Date() });
      }
    },
    getCertificateData: async (input: { certificate: Uint8Array }) => {
      const certificate = new X509Certificate(input.certificate);
      const thumbprint = await certificate.getThumbprint(crypto);
      const thumbprintHex = uint8ArrayToHex(new Uint8Array(thumbprint));
      return {
        issuerName: certificate.issuerName.toString(),
        subjectName: certificate.subjectName.toString(),
        pem: certificate.toString(),
        serialNumber: certificate.serialNumber,
        thumbprint: thumbprintHex,
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
      };
    },
  } satisfies X509Context,
};
