import * as z from "zod/mini";

const BOOLEAN_SCHEMA = z.boolean();
const CALLABLE_SCHEMA = z.function();
const NUMBER_SCHEMA = z.number();
const STRING_SCHEMA = z.string();

type RuntimeProperty =
  | bigint
  | boolean
  | null
  | number
  | object
  | string
  | symbol
  | undefined;

export function booleanFrom<Value>(value: Value): boolean | undefined {
  const result = BOOLEAN_SCHEMA.safeParse(value);
  return result.success ? result.data : undefined;
}

export function callableFrom<Value>(value: Value) {
  const result = CALLABLE_SCHEMA.safeParse(value);
  return result.success ? result.data : undefined;
}

export function numberFrom<Value>(value: Value): number | undefined {
  const result = NUMBER_SCHEMA.safeParse(value);
  return result.success ? result.data : undefined;
}

export function stringFrom<Value>(value: Value): string | undefined {
  const result = STRING_SCHEMA.safeParse(value);
  return result.success ? result.data : undefined;
}

export function unknownArrayFrom<Value>(value: Value) {
  try {
    if (!Array.isArray(value)) return undefined;
    const length = value.length;
    if (!Number.isSafeInteger(length)) return undefined;
    const snapshot: RuntimeProperty[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, index);
      if (descriptor === undefined) return undefined;
      snapshot.push(
        "value" in descriptor ? descriptor.value : descriptor.get?.call(value),
      );
    }
    return snapshot;
  } catch {
    return undefined;
  }
}

export function plainRecordFrom<Value>(value: Value) {
  try {
    if (value === null || Array.isArray(value)) return undefined;
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return undefined;
    // SAFETY: an exact Object/null prototype establishes the plain-record
    // owner consumed below; primitives, functions, and class instances have
    // already been rejected without reading caller-controlled properties.
    const owner = value as object;
    return Object.freeze({
      owner,
      has(key: string): boolean {
        return Object.hasOwn(owner, key);
      },
      read(key: string): RuntimeProperty {
        const descriptor = Object.getOwnPropertyDescriptor(owner, key);
        if (descriptor === undefined) return undefined;
        if ("value" in descriptor) return descriptor.value;
        return descriptor.get?.call(owner);
      },
    });
  } catch {
    return undefined;
  }
}
