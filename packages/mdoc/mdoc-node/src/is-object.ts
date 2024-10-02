function isObjectLike(value: unknown) {
  return typeof value === 'object' && value !== null;
}

export default function isObject<T = object>(input: unknown): input is T {
  if (
    !isObjectLike(input) ||
    Object.prototype.toString.call(input) !== '[object Object]'
  ) {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}
