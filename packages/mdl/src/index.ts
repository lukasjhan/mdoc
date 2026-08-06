export {
  type AgeAttestation,
  ageAt,
  buildAgeAttestations,
  readAgeAttestations,
  resolveAgeAttestation,
} from './age'
export {
  type DrivingPrivilege,
  type DrivingPrivilegeCode,
  privilegesFor,
  readDrivingPrivileges,
} from './driving-privileges'
export {
  type AgeOverIdentifier,
  EYE_COLOURS,
  type EyeColour,
  HAIR_COLOURS,
  type HairColour,
  jurisdictionNamespace,
  MDL_DOC_TYPE,
  MDL_MANDATORY_ELEMENTS,
  MDL_NAMESPACE,
  MDL_OPTIONAL_ELEMENTS,
  type MdlElementIdentifier,
  type MdlMandatoryElementIdentifier,
  type MdlOptionalElementIdentifier,
  parseAgeOverIdentifier,
  Sex,
  type SexValue,
} from './elements'
export { findMissingMandatoryElements, isExpired, isNotYetValid } from './profile'
