import {
  Component,
  computed,
  effect,
  inject,
  signal,
  untracked
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { map } from 'rxjs';
import { AutoCompleteModule, AutoCompleteCompleteEvent } from 'primeng/autocomplete';
import { TableModule } from 'primeng/table';
import { TagModule } from 'primeng/tag';
import { ButtonModule } from 'primeng/button';
import { TooltipModule } from 'primeng/tooltip';
import { IconFieldModule } from 'primeng/iconfield';
import { InputIconModule } from 'primeng/inputicon';
import { InputTextModule } from 'primeng/inputtext';
import { MessageModule } from 'primeng/message';
import { ProgressSpinnerModule } from 'primeng/progressspinner';

import { Issuer } from '../issuers/issuers-service';
import { IssuersStore } from '../issuers/issuers-store';

// Throwaway mock for the offers section — the offers wiring lands in a
// follow-up.
interface MockOffer {
  id: string;
  vct: string;
  state: 'pending' | 'issued' | 'cancelled' | 'expired';
  created_at: string;
  expires_at: string;
  issued_at: string | null;
}

@Component({
  selector: 'app-credential-offers-list',
  standalone: true,
  imports: [
    FormsModule,
    AutoCompleteModule,
    TableModule,
    TagModule,
    ButtonModule,
    TooltipModule,
    IconFieldModule,
    InputIconModule,
    InputTextModule,
    MessageModule,
    ProgressSpinnerModule
  ],
  templateUrl: './credential-offers-list.html',
  styleUrl: './credential-offers-list.scss'
})
export class CredentialOffersList {
  private readonly store = inject(IssuersStore);
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);

  protected readonly issuers = this.store.issuers;
  protected readonly issuersLoading = this.store.listLoading;
  protected readonly issuersError = this.store.listError;

  // URL is the source of truth for the current selection. `selectedIssuer`
  // is a view onto (store list × ?issuerId=), and user picks write back to
  // the URL via `onIssuerChange`.
  private readonly issuerIdParam = toSignal(
    this.route.queryParamMap.pipe(map((p) => p.get('issuerId'))),
    { initialValue: null }
  );

  protected readonly selectedIssuer = computed<Issuer | null>(() => {
    const id = this.issuerIdParam();
    if (!id) {
      return null;
    }
    return this.issuers().find((issuer) => issuer.id === id) ?? null;
  });

  protected readonly issuerSuggestions = signal<Issuer[]>([]);

  constructor() {
    this.store.load();

    // If there is exactly one issuer and the URL doesn't already name one,
    // adopt it as the selection. Writes through the URL so the
    // `selectedIssuer` computed re-evaluates from the same source.
    effect(() => {
      if (this.issuersLoading()) {
        return;
      }
      if (this.issuerIdParam()) {
        return;
      }
      const list = this.issuers();
      if (list.length !== 1) {
        return;
      }
      const only = list[0];
      untracked(() => this.setIssuerInUrl(only.id, true));
    });
  }

  protected onIssuerChange(issuer: Issuer | null): void {
    this.setIssuerInUrl(issuer?.id ?? null, false);
  }

  protected searchIssuers(event: AutoCompleteCompleteEvent): void {
    const q = event.query.trim().toLowerCase();
    const all = this.issuers();
    if (q === '') {
      this.issuerSuggestions.set(all);
      return;
    }
    this.issuerSuggestions.set(
      all.filter(
        (issuer) =>
          issuer.display_name.toLowerCase().includes(q) ||
          issuer.did.toLowerCase().includes(q)
      )
    );
  }

  protected reloadIssuers(): void {
    this.store.load();
  }

  private setIssuerInUrl(id: string | null, replaceUrl: boolean): void {
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { issuerId: id },
      queryParamsHandling: 'merge',
      replaceUrl
    });
  }

  protected readonly offers = signal<MockOffer[]>([
    {
      id: 'offer_aB7xKp9qR2tL5n',
      vct: 'urn:swiyu:driving-licence:v1',
      state: 'pending',
      created_at: '2026-05-28T09:14:00Z',
      expires_at: '2026-05-29T09:14:00Z',
      issued_at: null
    },
    {
      id: 'offer_cD8yLq0rS3uM6o',
      vct: 'urn:swiyu:driving-licence:v1',
      state: 'issued',
      created_at: '2026-05-27T17:42:00Z',
      expires_at: '2026-05-28T17:42:00Z',
      issued_at: '2026-05-27T17:50:11Z'
    },
    {
      id: 'offer_eF9zMr1sT4vN7p',
      vct: 'urn:swiyu:driving-licence:v1',
      state: 'cancelled',
      created_at: '2026-05-26T12:00:00Z',
      expires_at: '2026-05-27T12:00:00Z',
      issued_at: null
    },
    {
      id: 'offer_gH0aNs2tU5wO8q',
      vct: 'urn:swiyu:driving-licence:v1',
      state: 'expired',
      created_at: '2026-05-20T08:30:00Z',
      expires_at: '2026-05-21T08:30:00Z',
      issued_at: null
    }
  ]);

  protected stateSeverity(
    state: MockOffer['state']
  ): 'info' | 'success' | 'secondary' | 'warn' {
    switch (state) {
      case 'pending':
        return 'info';
      case 'issued':
        return 'success';
      case 'cancelled':
        return 'secondary';
      case 'expired':
        return 'warn';
    }
  }
}
