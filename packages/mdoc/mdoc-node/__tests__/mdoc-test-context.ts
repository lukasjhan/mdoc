import { p256 } from '@noble/curves/p256';
import { hkdf } from '@panva/hkdf';
import { X509Certificate, X509ChainBuilder } from '@peculiar/x509';
import type { MdocContext, X509Context } from '@protokoll/mdoc-client';
import { uint8ArrayToBase64Url } from '@protokoll/mdoc-client';
import { Buffer } from 'buffer';
import * as jose from 'jose';
import { importX509 } from 'jose';
import { signWithJwk } from '../src/sign.js';
import { verifyWithJwk } from '../src/verify.js';

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
          Buffer.from(privateKey).toString('hex'),
          Buffer.from(publicKey).toString('hex'),
          true
        )
        .slice(1);
      const salt = new Uint8Array(
        await crypto.subtle.digest('SHA-256', sessionTranscriptBytes)
      );
      const info = Buffer.from('EMacKey', 'utf-8');
      const result = await hkdf('sha256', ikm, salt, info, 32);

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
        jwk.alg = jwk.alg ?? alg;
        return await signWithJwk(jwk, data);
      },
      verify: async input => {
        const { mac0, jwk, options } = input;
        const { data, signature, alg } = mac0.getRawVerificationData(options);
        jwk.alg = jwk.alg ?? alg;
        return verifyWithJwk(jwk, signature, data);
      },
    },
    sign1: {
      sign: async input => {
        const { jwk, sign1 } = input;
        const { data, alg } = sign1.getRawSigningData();
        jwk.alg = jwk.alg ?? alg;
        return await signWithJwk(jwk, data);
      },
      verify: async input => {
        const { sign1, jwk, options } = input;
        const { data, signature, alg } = sign1.getRawVerificationData(options);
        jwk.alg = jwk.alg ?? alg;
        return verifyWithJwk(jwk, signature, data);
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
      return jose.exportJWK(key);
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
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-explicit-any
          await certificate.getThumbprint(crypto as any)
        ).toString('hex'),
      };
    },
    getCertificateValidityData: (input: { certificate: Uint8Array }) => {
      const certificate = new X509Certificate(input.certificate);
      return {
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
      };
    },
  } satisfies X509Context,
};
