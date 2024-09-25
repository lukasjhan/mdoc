import { AusweisError } from '@protokoll/core';

export class JarmError extends AusweisError {}

export class JarmErrorResponseError extends JarmError {}
export class JarmAuthResponseValidationError extends JarmError {}
