import { SENTINEL, buildClaimSkeleton } from './claim-skeleton';

describe('buildClaimSkeleton', () => {
  it('builds a flat object with typed sentinels', () => {
    const schema = {
      type: 'object',
      properties: {
        name: { type: 'string' },
        age: { type: 'integer' },
        score: { type: 'number' },
        active: { type: 'boolean' },
      },
    };
    expect(buildClaimSkeleton(schema)).toEqual({
      name: SENTINEL,
      age: 0,
      score: 0,
      active: false,
    });
  });

  it('recurses into nested objects and arrays', () => {
    const schema = {
      type: 'object',
      properties: {
        address: {
          type: 'object',
          properties: {
            street: { type: 'string' },
            zip: { type: 'integer' },
          },
        },
        tags: { type: 'array', items: { type: 'string' } },
      },
    };
    expect(buildClaimSkeleton(schema)).toEqual({
      address: { street: SENTINEL, zip: 0 },
      tags: [SENTINEL],
    });
  });

  it('uses the first enum member and a const value', () => {
    const schema = {
      type: 'object',
      properties: {
        color: { enum: ['red', 'green', 'blue'] },
        kind: { const: 'fixed' },
      },
    };
    expect(buildClaimSkeleton(schema)).toEqual({
      color: 'red',
      kind: 'fixed',
    });
  });

  it('prefers the first non-null member of a type union', () => {
    const schema = {
      type: 'object',
      properties: {
        middle_name: { type: ['string', 'null'] },
      },
    };
    expect(buildClaimSkeleton(schema)).toEqual({ middle_name: SENTINEL });
  });

  it('falls back to string sentinels for required keys without a properties block', () => {
    const schema = { type: 'object', required: ['given_name', 'family_name'] };
    expect(buildClaimSkeleton(schema)).toEqual({
      given_name: SENTINEL,
      family_name: SENTINEL,
    });
  });

  it('treats a node with properties but no explicit type as an object', () => {
    const schema = { properties: { id: { type: 'string' } } };
    expect(buildClaimSkeleton(schema)).toEqual({ id: SENTINEL });
  });

  it('falls back to {} for $ref and combinators', () => {
    expect(buildClaimSkeleton({ $ref: '#/$defs/Person' })).toEqual({});
    expect(buildClaimSkeleton({ oneOf: [{ type: 'string' }, { type: 'number' }] })).toEqual({});
    const nested = {
      type: 'object',
      properties: { choice: { anyOf: [{ type: 'string' }] } },
    };
    expect(buildClaimSkeleton(nested)).toEqual({ choice: {} });
  });

  it('emits an empty array when items is not a concrete schema', () => {
    expect(buildClaimSkeleton({ type: 'array' })).toEqual([]);
  });

  it('returns {} for non-object schema input', () => {
    expect(buildClaimSkeleton(null)).toEqual({});
    expect(buildClaimSkeleton('not a schema')).toEqual({});
    expect(buildClaimSkeleton(42)).toEqual({});
    expect(buildClaimSkeleton([{ type: 'string' }])).toEqual({});
  });

  it('returns the typed sentinel for a bare scalar schema', () => {
    expect(buildClaimSkeleton({ type: 'string' })).toEqual(SENTINEL);
    expect(buildClaimSkeleton({ type: 'boolean' })).toEqual(false);
    expect(buildClaimSkeleton({ type: 'null' })).toEqual(null);
  });
});
