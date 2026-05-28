import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export type CredentialOfferState =
  | 'pending'
  | 'issued'
  | 'cancelled'
  | 'expired';

// What the BFF list endpoint returns per item: the full offer minus `claims`.
// The detail endpoint adds `claims`.
export interface CredentialOfferSummary {
  id: string;
  issuer_id: string;
  vct: string;
  credential_type_id?: string;
  state: CredentialOfferState;
  expires_at: string;
  created_at: string;
  issued_at: string | null;
  cancelled_at: string | null;
}

export interface CredentialOffer extends CredentialOfferSummary {
  claims: Record<string, unknown>;
}

export interface CredentialOffersResponse {
  items: CredentialOfferSummary[];
  next_cursor: string | null;
}

export interface ListOptions {
  limit?: number;
  cursor?: string | null;
}

@Injectable({ providedIn: 'root' })
export class CredentialOffersService {
  private readonly http = inject(HttpClient);

  list(
    issuerId: string,
    options?: ListOptions
  ): Observable<CredentialOffersResponse> {
    let params = new HttpParams();
    if (options?.limit !== undefined) {
      params = params.set('limit', String(options.limit));
    }
    if (options?.cursor) {
      params = params.set('cursor', options.cursor);
    }
    return this.http.get<CredentialOffersResponse>(
      `/api/issuers/${issuerId}/credential-offers`,
      { params }
    );
  }

  get(issuerId: string, offerId: string): Observable<CredentialOffer> {
    return this.http.get<CredentialOffer>(
      `/api/issuers/${issuerId}/credential-offers/${offerId}`
    );
  }
}
