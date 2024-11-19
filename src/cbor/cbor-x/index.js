export {
  Decoder,
  FLOAT32_OPTIONS,
  Tag,
  clearSource,
  decode,
  decodeMultiple,
  isNativeAccelerationEnabled,
  roundFloat32,
  setSizeLimits,
} from './decode.js'
export {
  ALWAYS,
  DECIMAL_FIT,
  DECIMAL_ROUND,
  Encoder,
  NEVER,
  REUSE_BUFFER_MODE,
  addExtension,
  encode,
  encodeAsAsyncIterable,
  encodeAsIterable,
} from './encode.js'
export { decodeIter, encodeIter } from './iterators.js'
