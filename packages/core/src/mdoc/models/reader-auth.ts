import type { MdocContext } from '../../context'
import { Sign1, type Sign1Structure } from '../../cose/sign1'
import { defaultVerificationCallback, onCategoryCheck, type VerificationCallback } from '../check-callback'
import { ReaderAuthentication, type ReaderAuthenticationOptions } from './reader-authentication'

export type ReaderAuthStructure = Sign1Structure

export class ReaderAuth extends Sign1 {
  public async verify(
    options: {
      readerAuthentication: ReaderAuthentication | ReaderAuthenticationOptions
      verificationCallback?: VerificationCallback
    },
    ctx: Pick<MdocContext, 'cose' | 'x509'>
  ) {
    const readerAuthentication =
      options.readerAuthentication instanceof ReaderAuthentication
        ? options.readerAuthentication
        : new ReaderAuthentication(options.readerAuthentication)

    const verificationCallback = options.verificationCallback ?? defaultVerificationCallback

    const onCheck = onCategoryCheck(verificationCallback, 'READER_AUTH')

    const withContent = this.withDetachedContent(readerAuthentication.encode({ asDataItem: true }))

    const isValid = await withContent.verifySignature({}, ctx)

    onCheck({
      status: isValid ? 'PASSED' : 'FAILED',
      check: 'Signature is invalid on the reader auth',
      reason: 'Signature is invalid on the reader auth',
    })
  }
}
