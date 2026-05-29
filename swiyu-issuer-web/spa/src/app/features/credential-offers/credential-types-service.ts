import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

// A credential type assigned to an issuer, as returned by the BFF list
// endpoint. The `claim_schema` blob is deliberately omitted from this list
// response; it is fetched on demand via `schema()`.
export interface CredentialType {
  credential_type_id: string;
  vct: string;
  internal_description: string | null;
  claim_schema_source_url: string | null;
  claim_schema_fetched_at: string | null;
  default_validity_seconds: number;
  revocation_mode: string;
  created_at: string;
  updated_at: string;
  retired_at: string | null;
}

export interface CredentialTypesResponse {
  items: CredentialType[];
  next_cursor: string | null;
}

// A JSON Schema is opaque to the SPA; Monaco and the skeleton generator
// consume it as-is.
export type ClaimSchema = Record<string, unknown>;

@Injectable({ providedIn: 'root' })
export class CredentialTypesService {
  private readonly http = inject(HttpClient);

  listForIssuer(issuerId: string): Observable<CredentialTypesResponse> {
    return this.http.get<CredentialTypesResponse>(`/api/issuers/${issuerId}/credential-types`);
  }

  schema(credentialTypeId: string): Observable<ClaimSchema> {
    return this.http.get<ClaimSchema>(`/api/credential-types/${credentialTypeId}/schema`);
  }
}
