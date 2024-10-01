import { Mac0, Sign1 } from '@auth0/cose';
import { X509Certificate, X509ChainBuilder } from '@peculiar/x509';
import type { MdocContext, X509Context } from '@protokoll/mdoc-client';
import * as jose from 'jose';
import { importX509 } from 'jose';
import crypto from 'node:crypto';

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

      // Generate shared secret
      const ecdh = crypto.createECDH('prime256v1');
      ecdh.setPrivateKey(privateKey);
      const sharedSecret = ecdh.computeSecret(publicKey);
      const ikm = sharedSecret.slice(1); // Remove the first byte as in the original code

      const salt = new Uint8Array(
        await crypto.subtle.digest('SHA-256', sessionTranscriptBytes)
      );
      const info = Buffer.from('EMacKey', 'utf-8');

      // Create HKDF params
      const hkdfParams = {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt,
        info: info,
      };

      // Import the IKM as a CryptoKey
      const ikmKey = await crypto.subtle.importKey(
        'raw',
        ikm,
        { name: 'HKDF' },
        false,
        ['deriveBits']
      );

      // Perform HKDF using deriveBits
      const derivedBits = await crypto.subtle.deriveBits(
        hkdfParams,
        ikmKey,
        256 // 32 bytes * 8 bits/byte = 256 bits
      );

      // Convert the key material to a CryptoKey
      const cryptoKey = await crypto.subtle.importKey(
        'raw',
        derivedBits,
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
          const key = await jose.importJWK(jwk);
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
