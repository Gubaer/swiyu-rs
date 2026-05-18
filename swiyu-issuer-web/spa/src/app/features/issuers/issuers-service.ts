import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Issuer {
  id: string;
  did: string;
  state: string;
  description: string;
  display_name: string;
}

export interface IssuersResponse {
  items: Issuer[];
  next_cursor: string | null;
}

@Injectable({ providedIn: 'root' })
export class IssuersService {
  private readonly http = inject(HttpClient);

  list(): Observable<IssuersResponse> {
    return this.http.get<IssuersResponse>('/api/issuers');
  }
}
