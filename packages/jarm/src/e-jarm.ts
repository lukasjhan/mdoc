import { AusweisError } from '@protokoll/core';

export class JarmError extends AusweisError {}

export class JarmReceivedErrorResponse extends JarmError {}
export class JarmResponseMetadataValidationError extends JarmError {
  constructor(opts: { message: string; cause?: unknown }) {
    super({ code: 'BAD_REQUEST', ...opts });
  }
}
export class JarmAuthResponseValidationError extends JarmError {
  constructor(opts: { message: string; cause?: unknown }) {
    super({ code: 'BAD_REQUEST', ...opts });
  }
}
