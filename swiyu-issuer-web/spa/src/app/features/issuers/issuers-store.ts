import { Injectable, computed, inject, signal } from '@angular/core';
import { TranslocoService } from '@jsverse/transloco';
import { MessageService } from 'primeng/api';
import { Subscription, switchMap, take, takeWhile, timer } from 'rxjs';

import {
  CreateIssuerRequest,
  Issuer,
  IssuersService
} from './issuers-service';

// A create-issuer operation tracked client-side. Lives only for this browser
// session: the management API has no "list operation-tasks" endpoint, so the
// only creations we can show are the ones this tab initiated.
export type CreationStatus = 'in_progress' | 'failed';

export interface IssuerCreation {
  // Stable client-side key, assigned on optimistic insert and never changed.
  key: string;
  taskId: string | null;
  issuerId: string | null;
  display_name: string;
  description: string;
  status: CreationStatus;
  error: string | null;
}

const POLL_INTERVAL_MS = 1500;
// ~2 minutes of polling before giving up on a stuck saga.
const MAX_POLLS = 80;

@Injectable({ providedIn: 'root' })
export class IssuersStore {
  private readonly service = inject(IssuersService);
  private readonly messages = inject(MessageService);
  private readonly transloco = inject(TranslocoService);

  // "Ready" tab: the server truth, replaced wholesale on every load().
  private readonly readyIssuers = signal<Issuer[]>([]);
  // "In progress" tab: client-tracked creations (in_progress + failed).
  private readonly trackedCreations = signal<IssuerCreation[]>([]);

  readonly issuers = this.readyIssuers.asReadonly();
  readonly creations = this.trackedCreations.asReadonly();
  readonly inProgressCount = computed(() => this.trackedCreations().length);
  readonly listLoading = signal(false);
  readonly listError = signal<string | null>(null);

  private readonly polls = new Map<string, Subscription>();

  load(): void {
    this.listLoading.set(true);
    this.listError.set(null);
    this.service.list().subscribe({
      next: (resp) => {
        this.readyIssuers.set(resp.items);
        this.listLoading.set(false);
      },
      error: () => {
        this.listError.set(this.t('issuer.list.load_error'));
        this.listLoading.set(false);
      }
    });
  }

  create(input: CreateIssuerRequest): void {
    const key = crypto.randomUUID();
    this.trackedCreations.update((rows) => [
      {
        key,
        taskId: null,
        issuerId: null,
        display_name: input.display_name,
        description: input.description,
        status: 'in_progress',
        error: null
      },
      ...rows
    ]);
    this.startRequest(key, input);
  }

  retry(key: string): void {
    const row = this.trackedCreations().find((r) => r.key === key);
    if (!row) {
      return;
    }
    this.patchCreation(key, {
      status: 'in_progress',
      error: null,
      taskId: null,
      issuerId: null
    });
    this.startRequest(key, {
      display_name: row.display_name,
      description: row.description
    });
  }

  dismiss(key: string): void {
    this.stopPoll(key);
    this.removeCreation(key);
  }

  private startRequest(key: string, input: CreateIssuerRequest): void {
    this.service.create(input).subscribe({
      next: ({ task_id, issuer_id }) => {
        this.patchCreation(key, { taskId: task_id, issuerId: issuer_id });
        this.poll(key, task_id, issuer_id);
      },
      error: () => this.markFailed(key, this.t('issuer.creation.error_request'))
    });
  }

  private poll(key: string, taskId: string, issuerId: string): void {
    let settled = false;
    const settle = (action: () => void) => {
      if (!settled) {
        settled = true;
        action();
      }
      this.stopPoll(key);
    };

    const sub = timer(0, POLL_INTERVAL_MS)
      .pipe(
        switchMap(() => this.service.getTask(taskId)),
        take(MAX_POLLS),
        takeWhile(
          (task) => task.state !== 'completed' && task.state !== 'failed',
          true
        )
      )
      .subscribe({
        next: (task) => {
          if (task.state === 'completed') {
            settle(() => this.finishSuccess(key, issuerId));
          } else if (task.state === 'failed') {
            const message =
              task.error_message ?? this.t('issuer.creation.error_generic');
            settle(() => this.markFailed(key, message));
          }
        },
        error: () =>
          settle(() => this.markFailed(key, this.t('issuer.creation.error_polling'))),
        complete: () =>
          settle(() => this.markFailed(key, this.t('issuer.creation.error_timeout')))
      });

    this.polls.set(key, sub);
  }

  private finishSuccess(key: string, issuerId: string): void {
    // The DID and canonical state only exist server-side, so re-fetch rather
    // than promote the optimistic data.
    this.service.get(issuerId).subscribe({
      next: (issuer) => {
        this.readyIssuers.update((list) => [
          issuer,
          ...list.filter((i) => i.id !== issuer.id)
        ]);
        this.removeCreation(key);
        this.messages.add({
          severity: 'success',
          summary: this.t('issuer.creation.toast_created', {
            name: issuer.display_name
          })
        });
      },
      error: () => this.markFailed(key, this.t('issuer.creation.error_fetch'))
    });
  }

  private markFailed(key: string, error: string): void {
    this.patchCreation(key, { status: 'failed', error });
  }

  private patchCreation(key: string, change: Partial<IssuerCreation>): void {
    this.trackedCreations.update((rows) =>
      rows.map((r) => (r.key === key ? { ...r, ...change } : r))
    );
  }

  private removeCreation(key: string): void {
    this.trackedCreations.update((rows) => rows.filter((r) => r.key !== key));
  }

  private stopPoll(key: string): void {
    this.polls.get(key)?.unsubscribe();
    this.polls.delete(key);
  }

  private t(key: string, params?: Record<string, unknown>): string {
    return this.transloco.translate(key, params);
  }
}
