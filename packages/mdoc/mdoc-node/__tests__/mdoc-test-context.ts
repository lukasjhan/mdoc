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
  crypto: {
    digest: ({ digestAlgorithm, bytes }) => {
      return subtle.digest(digestAlgorithm, bytes);
    },
    random: (length: number) => {
      return webcrypto.getRandomValues(new Uint8Array(length));
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
        await subtle.digest('SHA-256', sessionTranscriptBytes)
      );
      const info = Buffer.from('EMacKey', 'utf-8');
      const result = await hkdf('sha256', ikm, salt, info, 32);

      // Convert the key material to a CryptoKey
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        result,
        { name: 'HMAC', hash: 'SHA-256' },
        true,
        ['sign', 'verify']
      );

      // Export the CryptoKey as a JWK
      const jwk = await crypto.subtle.exportKey('jwk', cryptoKey);

      return jwk as jose.JWK;
    },
  },

  cose: {
    mac0: {
      sign: async input => {
        const { jwk, mac0 } = input;
        const key = await jose.importJWK(jwk);

        const _mac0 = await Mac0.create(
          mac0.protectedHeaders as any,
          mac0.unprotectedHeaders as any,
          mac0.payload,
          key
        );

        return _mac0.tag;
      },
      verify: async input => {
        try {
          const { mac0, jwk, options } = input;
          const key = await jose.importJWK(jwk);
          const _mac0 = new Mac0(
            mac0.protectedHeaders,
            mac0.unprotectedHeaders,
            mac0.payload,
            mac0.tag
          );
          await _mac0.verify(key, options);
          return true;
        } catch (errror) {
          return false;
        }
      },
    },
    sign1: {
      sign: async input => {
        const { sign1, jwk } = input;
        const key = await jose.importJWK(jwk);

        const _sign1 = await Sign1.sign(
          sign1.protectedHeaders as any,
          sign1.unprotectedHeaders as any,
          sign1.payload,
          key
        );
        return _sign1.signature;
      },
      verify: async input => {
        try {
          const { sign1, jwk, options } = input;
          console.log('herer', jwk);
          const key = await jose.importJWK(jwk);
          console.log('done');
          const _sign1 = new Sign1(
            sign1.protectedHeaders,
            sign1.unprotectedHeaders,
            sign1.payload,
            sign1.signature
          );
          await _sign1.verify(key, options);
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
          await certificate.getThumbprint(crypto)
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
