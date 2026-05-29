import { Injectable, inject, signal } from '@angular/core';

import { ClaimSchema, CredentialType, CredentialTypesService } from './credential-types-service';

// Backs the create-offer wizard's type picker and per-type schema fetch.
// Like CredentialOffersStore, every request is tagged with the "intended"
// id (issuer for the type list, type for the schema) and a response is only
// committed if the tag still matches when it arrives — so a stale response
// from a previous selection cannot clobber current state.
@Injectable({ providedIn: 'root' })
export class CredentialTypesStore {
  private readonly service = inject(CredentialTypesService);

  private readonly typesSignal = signal<CredentialType[]>([]);
  private readonly typesLoadingSignal = signal(false);
  private readonly typesErrorSignal = signal<string | null>(null);
  private intendedIssuerId: string | null = null;

  private readonly schemaSignal = signal<ClaimSchema | null>(null);
  private readonly schemaLoadingSignal = signal(false);
  private readonly schemaErrorSignal = signal<string | null>(null);
  private intendedTypeId: string | null = null;

  readonly types = this.typesSignal.asReadonly();
  readonly typesLoading = this.typesLoadingSignal.asReadonly();
  readonly typesError = this.typesErrorSignal.asReadonly();

  readonly schema = this.schemaSignal.asReadonly();
  readonly schemaLoading = this.schemaLoadingSignal.asReadonly();
  readonly schemaError = this.schemaErrorSignal.asReadonly();

  loadTypesFor(issuerId: string): void {
    this.intendedIssuerId = issuerId;
    this.typesSignal.set([]);
    this.typesErrorSignal.set(null);
    this.typesLoadingSignal.set(true);
    this.service.listForIssuer(issuerId).subscribe({
      next: (response) => {
        if (this.intendedIssuerId !== issuerId) {
          return;
        }
        this.typesSignal.set(response.items);
        this.typesLoadingSignal.set(false);
      },
      error: () => {
        if (this.intendedIssuerId !== issuerId) {
          return;
        }
        this.typesErrorSignal.set('Could not load credential types.');
        this.typesLoadingSignal.set(false);
      },
    });
  }

  clearTypes(): void {
    this.intendedIssuerId = null;
    this.typesSignal.set([]);
    this.typesErrorSignal.set(null);
    this.typesLoadingSignal.set(false);
  }

  loadSchema(credentialTypeId: string): void {
    this.intendedTypeId = credentialTypeId;
    this.schemaSignal.set(null);
    this.schemaErrorSignal.set(null);
    this.schemaLoadingSignal.set(true);
    this.service.schema(credentialTypeId).subscribe({
      next: (schema) => {
        if (this.intendedTypeId !== credentialTypeId) {
          return;
        }
        this.schemaSignal.set(schema);
        this.schemaLoadingSignal.set(false);
      },
      error: () => {
        if (this.intendedTypeId !== credentialTypeId) {
          return;
        }
        this.schemaErrorSignal.set('Could not load the credential type schema.');
        this.schemaLoadingSignal.set(false);
      },
    });
  }

  clearSchema(): void {
    this.intendedTypeId = null;
    this.schemaSignal.set(null);
    this.schemaErrorSignal.set(null);
    this.schemaLoadingSignal.set(false);
  }
}
