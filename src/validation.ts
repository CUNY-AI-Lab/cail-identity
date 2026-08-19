import * as z from "zod/mini";

const BOOLEAN_SCHEMA = z.boolean();
const CALLABLE_SCHEMA = z.function();
const NUMBER_SCHEMA = z.number();
const STRING_SCHEMA = z.string();
const UNKNOWN_ARRAY_SCHEMA = z.array(z.unknown());

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
  const result = UNKNOWN_ARRAY_SCHEMA.safeParse(value);
  return result.success ? result.data : undefined;
}

export function plainRecordFrom<Value>(value: Value) {
  try {
    if (value === null || Object(value) !== value || Array.isArray(value)) {
      return undefined;
    }
    // SAFETY: identity under Object coercion establishes that the original
    // value is an object or function; the prototype check below rejects
    // functions and class instances.
    const owner = value as object;
    const prototype = Object.getPrototypeOf(owner);
    if (prototype !== Object.prototype && prototype !== null) return undefined;
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
