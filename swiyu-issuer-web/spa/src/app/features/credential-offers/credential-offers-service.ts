import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export type CredentialOfferState = 'pending' | 'issued' | 'cancelled' | 'expired';

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

export interface CreateCredentialOfferRequest {
  credential_type_id: string;
  claims: Record<string, unknown>;
  expires_in_seconds?: number;
}

// The create response carries the one-time pre-auth code and deeplink. These
// are returned exactly once — only a hash is persisted server-side — so the SPA
// must surface them immediately and cannot re-fetch them.
export interface CreateCredentialOfferResult {
  id: string;
  pre_auth_code: string;
  offer_deeplink: string;
  expires_at: string;
}

@Injectable({ providedIn: 'root' })
export class CredentialOffersService {
  private readonly http = inject(HttpClient);

  list(issuerId: string, options?: ListOptions): Observable<CredentialOffersResponse> {
    let params = new HttpParams();
    if (options?.limit !== undefined) {
      params = params.set('limit', String(options.limit));
    }
    if (options?.cursor) {
      params = params.set('cursor', options.cursor);
    }
    return this.http.get<CredentialOffersResponse>(`/api/issuers/${issuerId}/credential-offers`, {
      params,
    });
  }

  get(issuerId: string, offerId: string): Observable<CredentialOffer> {
    return this.http.get<CredentialOffer>(`/api/issuers/${issuerId}/credential-offers/${offerId}`);
  }

  create(
    issuerId: string,
    body: CreateCredentialOfferRequest,
  ): Observable<CreateCredentialOfferResult> {
    return this.http.post<CreateCredentialOfferResult>(
      `/api/issuers/${issuerId}/credential-offers`,
      body,
    );
  }
}
