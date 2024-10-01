import { Mac0, Sign1 } from '@auth0/cose';
import { p256 } from '@noble/curves/p256';
import { hkdf } from '@panva/hkdf';
import { X509Certificate, X509ChainBuilder } from '@peculiar/x509';
import type { MdocContext, X509Context } from '@protokoll/mdoc-client';
import * as jose from 'jose';
import { importX509 } from 'jose';
import crypto from 'node:crypto';
import * as webcrypto from 'uncrypto';
import { subtle } from 'uncrypto';

export const mdocContext: MdocContext = {
  jose: {
    importJwk: async jwk => {
      return (await jose.importJWK(jwk)) as Uint8Array;
    },
  },
  crypto: {
    digest: ({ digestAlgorithm, bytes }) => {
      return subtle.digest(digestAlgorithm, bytes);
    },
    random: async (length: number) => {
      return webcrypto.getRandomValues(new Uint8Array(length));
    },
    calculateEphemeralMacKey: async input => {
      const { privateKey, publicKey, sessionTranscriptBytes } = input;

      const ikm = p256
        .getSharedSecret(
          Buffer.from(privateKey).toString('hex'),
          Buffer.from(publicKey).toString('hex'),
          true
        )
        .slice(1);
      const salt = new Uint8Array(
        await subtle.digest('SHA-256', sessionTranscriptBytes)
      );
      const info = Buffer.from('EMacKey', 'utf-8');
      const result = await hkdf('sha256', ikm, salt, info, 32);
      return result;
    },
  },

  cose: {
    mac0: {
      sign: async input => {
        const { protectedHeaders, unprotectedHeaders, payload, key } = input;

        const mac0 = await Mac0.create(
          protectedHeaders,
          unprotectedHeaders,
          payload,
          key
        );

        return mac0.tag;
      },
      verify: async input => {
        try {
          console.info('verify mac0');
          const mac0 = new Mac0(
            input.protectedHeaders,
            input.unprotectedHeaders,
            input.payload,
            input.tag
          );
          await mac0.verify(input.key, input.options);
          return true;
        } catch (errror) {
          return false;
        }
      },
    },
    sign1: {
      sign: async input => {
        const { protectedHeaders, unprotectedHeaders, payload, key } = input;

        const result = await Sign1.sign(
          protectedHeaders,
          unprotectedHeaders,
          payload,
          key
        );
        return result.signature;
      },
      verify: async input => {
        try {
          console.info('verify sign1');
          const sign1 = new Sign1(
            input.protectedHeaders,
            input.unprotectedHeaders,
            input.payload,
            input.signature
          );
          await sign1.verify(input.key, input.options);
          return true;
        } catch (errror) {
          return false;
        }
      },
    },
  },

  x509: {
    getIssuerName: (input: { certificate: Uint8Array }) => {
      const certificate = new X509Certificate(input.certificate);
      return certificate.issuerName;
    },
    getIssuerNameField: (input: { certificate: Uint8Array; field: string }) => {
      const certificate = new X509Certificate(input.certificate);
      return certificate.issuerName.getField(input.field);
    },
    getPublicKey: async (input: { certificate: Uint8Array; alg: string }) => {
      const certificate = new X509Certificate(input.certificate);
      const key = await importX509(certificate.toString(), input.alg);
      return key as any;
    },

    validateCertificateChain: async (input: {
      certificates: [string, ...string[]];
    }) => {
      const { certificates } = input;
      if (certificates.length === 0) {
        throw new Error('No root certificate found');
      }

      const parsedLeafCertificate = new X509Certificate(certificates[0]);
      const parsedCertificates = certificates.map(c => new X509Certificate(c));
      const certificateChainBuilder = new X509ChainBuilder({
        certificates: parsedCertificates,
      });

      const chain = await certificateChainBuilder.build(parsedLeafCertificate);

      // The chain is reversed here as the `x5c` header (the expected input),
      // has the leaf certificate as the first entry, while the `x509` library expects this as the last
      const parsedChain = chain
        .map(c => new X509Certificate(new Uint8Array(c.rawData)))
        .reverse();

      if (parsedChain.length !== certificates.length) {
        throw new Error(
          'Could not parse the full chain. Likely due to incorrect ordering'
        );
      }

      for (let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i];
        if (!cert) throw new Error('Could not parse certificate');
        const previousCertificate = parsedChain[i - 1];
        const publicKey = previousCertificate
          ? previousCertificate.publicKey
          : undefined;
        await cert.verify({ publicKey });
      }
    },
    getCertificateData: async (input: { certificate: Uint8Array }) => {
      const certificate = new X509Certificate(input.certificate);
      return {
        subjectName: certificate.subjectName.toString(),
        pem: certificate.toString(),
        serialNumber: certificate.serialNumber,
        thumbprint: Buffer.from(
          await certificate.getThumbprint(crypto)
        ).toString('hex'),
      };
    },
    getCertificateValidityData: async (input: { certificate: Uint8Array }) => {
      const certificate = new X509Certificate(input.certificate);
      return {
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
      };
    },
  } satisfies X509Context,
};
