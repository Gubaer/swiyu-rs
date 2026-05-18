import { Injectable, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

export interface Me {
  id: string;
  tenant_name: string;
}

@Injectable({ providedIn: 'root' })
export class MeService {
  private readonly http = inject(HttpClient);

  get(): Observable<Me> {
    return this.http.get<Me>('/api/me');
  }
}
