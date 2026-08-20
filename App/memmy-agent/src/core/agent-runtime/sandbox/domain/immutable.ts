function freezeValue<T>(value: T, seen: WeakSet<object>): T {
  if (!value || typeof value !== "object") return value;
  if (seen.has(value)) return value;
  seen.add(value);
  for (const nested of Object.values(value)) freezeValue(nested, seen);
  if (!Object.isFrozen(value)) Object.freeze(value);
  return value;
}

export function deepFreeze<T>(value: T): T {
  return freezeValue(value, new WeakSet());
}

export function immutableSnapshot<T>(value: T): T {
  return deepFreeze(structuredClone(value));
}
