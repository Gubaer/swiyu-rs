import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { CredentialTypesStore } from './credential-types-store';

describe('CredentialTypesStore', () => {
  let store: CredentialTypesStore;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    store = TestBed.inject(CredentialTypesStore);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('loads the type list for an issuer', () => {
    store.loadTypesFor('iss1');
    expect(store.typesLoading()).toBe(true);

    httpMock
      .expectOne('/api/issuers/iss1/credential-types')
      .flush({ items: [{ credential_type_id: 'ct1', vct: 'urn:x' }], next_cursor: null });

    expect(store.typesLoading()).toBe(false);
    expect(store.types().map((t) => t.credential_type_id)).toEqual(['ct1']);
  });

  it('drops a stale type response when the issuer changed mid-flight', () => {
    store.loadTypesFor('iss1');
    const stale = httpMock.expectOne('/api/issuers/iss1/credential-types');

    store.loadTypesFor('iss2');
    const fresh = httpMock.expectOne('/api/issuers/iss2/credential-types');

    // The first request resolves after the switch; its result must be ignored.
    stale.flush({ items: [{ credential_type_id: 'old', vct: 'urn:old' }], next_cursor: null });
    expect(store.types()).toEqual([]);

    fresh.flush({ items: [{ credential_type_id: 'new', vct: 'urn:new' }], next_cursor: null });
    expect(store.types().map((t) => t.credential_type_id)).toEqual(['new']);
  });

  it('sets an error message when the type list fails', () => {
    store.loadTypesFor('iss1');
    httpMock.expectOne('/api/issuers/iss1/credential-types').error(new ProgressEvent('network'));

    expect(store.typesError()).toBeTruthy();
    expect(store.typesLoading()).toBe(false);
  });

  it('loads a schema for a type and drops a stale schema response', () => {
    store.loadSchema('ct1');
    const stale = httpMock.expectOne('/api/credential-types/ct1/schema');

    store.loadSchema('ct2');
    const fresh = httpMock.expectOne('/api/credential-types/ct2/schema');

    stale.flush({ title: 'old' });
    expect(store.schema()).toBeNull();

    fresh.flush({ type: 'object' });
    expect(store.schema()).toEqual({ type: 'object' });
    expect(store.schemaLoading()).toBe(false);
  });
});
