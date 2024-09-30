import { MDLError } from './errors.js';

export interface VerificationAssessment {
  status: 'PASSED' | 'FAILED' | 'WARNING';
  category:
    | 'DOCUMENT_FORMAT'
    | 'DEVICE_AUTH'
    | 'ISSUER_AUTH'
    | 'DATA_INTEGRITY';
  check: string;
  reason?: string;
}

export type VerificationCallback = (item: VerificationAssessment) => void;
export type UserDefinedVerificationCallback = (
  item: VerificationAssessment,
  original: VerificationCallback
) => void;

export const defaultCallback: VerificationCallback = verification => {
  if (verification.status !== 'FAILED') return;
  throw new MDLError(verification.reason ?? verification.check);
};

export const buildCallback = (
  callback?: UserDefinedVerificationCallback
): VerificationCallback => {
  if (typeof callback === 'undefined') {
    return defaultCallback;
  }
  return (item: VerificationAssessment) => {
    callback(item, defaultCallback);
  };
};

export const onCatCheck = (
  onCheck: UserDefinedVerificationCallback,
  category: VerificationAssessment['category']
) => {
  return (item: Omit<VerificationAssessment, 'category'>) => {
    onCheck({ ...item, category }, defaultCallback);
  };
};
