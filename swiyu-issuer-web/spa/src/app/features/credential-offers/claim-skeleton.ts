// Builds a best-effort, schema-valid scaffold from a credential type's JSON
// Schema so the claims editor opens on a structured starting point instead of
// a blank buffer. Scalar values are obvious sentinels — visibly fake but
// schema-valid — so the editor starts green while signalling that every value
// must be replaced before the offer is real.
//
// "Best-effort" is deliberate: constructs this generator cannot resolve on its
// own (`$ref`, `oneOf`/`anyOf`/`allOf`) fall back to an empty object for that
// node rather than guessing. The backend remains the authoritative validator.

export const SENTINEL = 'REPLACE_ME';

type JsonSchema = Record<string, unknown>;

export function buildClaimSkeleton(schema: unknown): unknown {
  if (!isObject(schema)) {
    return {};
  }
  return skeletonForNode(schema);
}

function skeletonForNode(node: JsonSchema): unknown {
  // A fixed `const` is the only valid value, so use it outright.
  if ('const' in node) {
    return node['const'];
  }
  // For an `enum`, the first member is always valid.
  const enumValues = node['enum'];
  if (Array.isArray(enumValues) && enumValues.length > 0) {
    return enumValues[0];
  }
  // Combinators and references need resolution we don't do; fall back to {}.
  if ('$ref' in node || 'oneOf' in node || 'anyOf' in node || 'allOf' in node) {
    return {};
  }

  switch (resolveType(node['type'])) {
    case 'object':
      return skeletonForObject(node);
    case 'array':
      return skeletonForArray(node);
    case 'string':
      return SENTINEL;
    case 'integer':
    case 'number':
      return 0;
    case 'boolean':
      return false;
    case 'null':
      return null;
    default:
      // No usable `type`. Treat it as an object if it carries object-shaped
      // hints, otherwise give up on this node with {}.
      if (isObject(node['properties']) || Array.isArray(node['required'])) {
        return skeletonForObject(node);
      }
      return {};
  }
}

function skeletonForObject(node: JsonSchema): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  const properties = node['properties'];
  if (isObject(properties)) {
    for (const [key, child] of Object.entries(properties)) {
      result[key] = isObject(child) ? skeletonForNode(child) : {};
    }
    return result;
  }

  // No `properties` block: we can still surface the required keys, but without
  // per-key schemas the best we can do is a string sentinel for each.
  const required = node['required'];
  if (Array.isArray(required)) {
    for (const key of required) {
      if (typeof key === 'string') {
        result[key] = SENTINEL;
      }
    }
  }
  return result;
}

function skeletonForArray(node: JsonSchema): unknown[] {
  // A single skeleton element shows the item shape when `items` is a concrete
  // schema; otherwise an empty array (always valid when no minItems applies).
  const items = node['items'];
  if (isObject(items)) {
    return [skeletonForNode(items)];
  }
  return [];
}

// `type` may be a single string or a union array (e.g. ["string", "null"]).
// Prefer the first non-null member so the placeholder is a concrete value.
function resolveType(raw: unknown): string | undefined {
  if (typeof raw === 'string') {
    return raw;
  }
  if (Array.isArray(raw)) {
    const preferred = raw.find((t) => typeof t === 'string' && t !== 'null') ?? raw[0];
    return typeof preferred === 'string' ? preferred : undefined;
  }
  return undefined;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
