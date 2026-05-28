import { Injectable, computed, inject, signal } from '@angular/core';

import {
  CredentialOfferSummary,
  CredentialOffersService
} from './credential-offers-service';

// Tracks per-issuer paging state for the offers table. The "intended" issuer
// id is the source-of-truth tag: every request reads it on dispatch, and the
// response is only committed if the tag still matches when it arrives. That
// keeps a stale response from a previously selected issuer (or from a request
// that was in flight when the user switched issuers) from clobbering current
// state.
@Injectable({ providedIn: 'root' })
export class CredentialOffersStore {
  private readonly service = inject(CredentialOffersService);

  private readonly itemsSignal = signal<CredentialOfferSummary[]>([]);
  private readonly nextCursorSignal = signal<string | null>(null);
  private readonly loadingSignal = signal(false);
  private readonly errorSignal = signal<string | null>(null);
  private intendedIssuerId: string | null = null;

  readonly items = this.itemsSignal.asReadonly();
  readonly nextCursor = this.nextCursorSignal.asReadonly();
  readonly loading = this.loadingSignal.asReadonly();
  readonly error = this.errorSignal.asReadonly();
  readonly hasMore = computed(() => this.nextCursorSignal() !== null);

  loadFor(issuerId: string): void {
    this.intendedIssuerId = issuerId;
    this.itemsSignal.set([]);
    this.nextCursorSignal.set(null);
    this.errorSignal.set(null);
    this.loadingSignal.set(true);
    this.service.list(issuerId).subscribe({
      next: (response) => {
        if (this.intendedIssuerId !== issuerId) {
          // The selection changed while this request was in flight; the
          // newer loadFor has already reset state, so just drop this result.
          return;
        }
        this.itemsSignal.set(response.items);
        this.nextCursorSignal.set(response.next_cursor);
        this.loadingSignal.set(false);
      },
      error: () => {
        if (this.intendedIssuerId !== issuerId) {
          return;
        }
        this.errorSignal.set('Could not load credential offers.');
        this.loadingSignal.set(false);
      }
    });
  }

  loadMore(): void {
    const issuerId = this.intendedIssuerId;
    const cursor = this.nextCursorSignal();
    if (!issuerId || !cursor || this.loadingSignal()) {
      return;
    }
    this.loadingSignal.set(true);
    this.service.list(issuerId, { cursor }).subscribe({
      next: (response) => {
        if (this.intendedIssuerId !== issuerId) {
          return;
        }
        this.itemsSignal.update((items) => [...items, ...response.items]);
        this.nextCursorSignal.set(response.next_cursor);
        this.loadingSignal.set(false);
      },
      error: () => {
        if (this.intendedIssuerId !== issuerId) {
          return;
        }
        // Cursor rejected or transient failure. Surface a generic message;
        // recovery is to refresh from page 1, dropping the bad cursor.
        this.errorSignal.set('Could not load more credential offers.');
        this.loadingSignal.set(false);
      }
    });
  }

  refresh(): void {
    if (this.intendedIssuerId) {
      this.loadFor(this.intendedIssuerId);
    }
  }

  clear(): void {
    this.intendedIssuerId = null;
    this.itemsSignal.set([]);
    this.nextCursorSignal.set(null);
    this.errorSignal.set(null);
    this.loadingSignal.set(false);
  }
}
