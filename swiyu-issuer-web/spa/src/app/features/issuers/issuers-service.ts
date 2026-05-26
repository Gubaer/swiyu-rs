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

export interface CreateIssuerRequest {
  display_name: string;
  description: string;
}

export interface CreateIssuerResponse {
  task_id: string;
  issuer_id: string;
}

export type OperationTaskState =
  | 'pending'
  | 'in_progress'
  | 'completed'
  | 'failed';

export interface OperationTask {
  id: string;
  task_type: string;
  state: OperationTaskState;
  error_code: string | null;
  error_message: string | null;
}

export interface DeactivateIssuerResponse {
  // null when the issuer was already deactivated and no task was needed.
  task_id: string | null;
  issuer_id: string;
}

export interface RotateKeysResponse {
  task_id: string;
  issuer_id: string;
}

@Injectable({ providedIn: 'root' })
export class IssuersService {
  private readonly http = inject(HttpClient);

  list(): Observable<IssuersResponse> {
    return this.http.get<IssuersResponse>('/api/issuers');
  }

  get(issuerId: string): Observable<Issuer> {
    return this.http.get<Issuer>(`/api/issuers/${issuerId}`);
  }

  create(body: CreateIssuerRequest): Observable<CreateIssuerResponse> {
    return this.http.post<CreateIssuerResponse>('/api/issuers', body);
  }

  getTask(taskId: string): Observable<OperationTask> {
    return this.http.get<OperationTask>(`/api/operation-tasks/${taskId}`);
  }

  deactivate(issuerId: string): Observable<DeactivateIssuerResponse> {
    return this.http.post<DeactivateIssuerResponse>(
      `/api/issuers/${issuerId}/deactivate`,
      {}
    );
  }

  rotateKeys(issuerId: string): Observable<RotateKeysResponse> {
    // "all" rotates every key role (authorized, authentication, assertion).
    return this.http.post<RotateKeysResponse>(
      `/api/issuers/${issuerId}/rotate-keys`,
      { roles: ['all'] }
    );
  }
}
