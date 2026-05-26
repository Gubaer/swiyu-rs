import { Injectable, computed, inject, signal } from '@angular/core';
import { TranslocoService } from '@jsverse/transloco';
import { MessageService } from 'primeng/api';
import { Subscription } from 'rxjs';

import { CreateIssuerRequest, Issuer, IssuersService } from './issuers-service';
import { pollOperationTask } from './operation-task-poll';

// A long-running issuer operation (create or deactivate) tracked client-side.
// Lives only for this browser session: the management API has no "list
// operation-tasks" endpoint, so the only operations we can show are the ones
// this tab initiated.
export type OperationKind = 'create' | 'deactivate' | 'rotate_keys';
export type OperationStatus = 'in_progress' | 'failed';

export interface TrackedOperation {
  // Stable client-side key, assigned on insert and never changed.
  key: string;
  kind: OperationKind;
  // Display name shown in the "In progress" tab row.
  label: string;
  status: OperationStatus;
  error: string | null;
  // Known up-front for deactivate; filled in after the POST for create.
  issuerId: string | null;
  taskId: string | null;
  // Kept for retry of a failed create; null for deactivate.
  createInput: CreateIssuerRequest | null;
}

const SUCCESS_TOAST_KEYS: Record<OperationKind, string> = {
  create: 'issuer.operation.created_toast',
  deactivate: 'issuer.operation.deactivated_toast',
  rotate_keys: 'issuer.operation.rotated_toast'
};

// Active issuers first, then by display name (case-insensitive,
// locale-aware). Returns a new array.
function sortIssuers(issuers: Issuer[]): Issuer[] {
  return [...issuers].sort((a, b) => {
    const stateRank = (issuer: Issuer) => (issuer.state === 'active' ? 0 : 1);
    const byState = stateRank(a) - stateRank(b);
    if (byState !== 0) {
      return byState;
    }
    return a.display_name.localeCompare(b.display_name, undefined, {
      sensitivity: 'base'
    });
  });
}

@Injectable({ providedIn: 'root' })
export class IssuersStore {
  private readonly service = inject(IssuersService);
  private readonly messages = inject(MessageService);
  private readonly transloco = inject(TranslocoService);

  // "Ready" tab: the server truth, replaced wholesale on every load().
  private readonly readyIssuers = signal<Issuer[]>([]);
  // "In progress" tab: client-tracked operations (in_progress + failed).
  private readonly trackedOperations = signal<TrackedOperation[]>([]);

  readonly issuers = this.readyIssuers.asReadonly();
  readonly operations = this.trackedOperations.asReadonly();
  readonly inProgressCount = computed(() => this.trackedOperations().length);
  readonly listLoading = signal(false);
  readonly listError = signal<string | null>(null);

  private readonly polls = new Map<string, Subscription>();

  load(): void {
    this.listLoading.set(true);
    this.listError.set(null);
    this.service.list().subscribe({
      next: (resp) => {
        this.readyIssuers.set(sortIssuers(resp.items));
        this.listLoading.set(false);
      },
      error: () => {
        this.listError.set(this.t('issuer.list.load_error'));
        this.listLoading.set(false);
      }
    });
  }

  // Insert or replace a single issuer in the ready list, keeping it sorted.
  upsertIssuer(issuer: Issuer): void {
    this.readyIssuers.update((list) =>
      sortIssuers([issuer, ...list.filter((i) => i.id !== issuer.id)])
    );
  }

  create(input: CreateIssuerRequest): void {
    const key = this.insertOperation({
      kind: 'create',
      label: input.display_name,
      issuerId: null,
      createInput: input
    });
    this.startCreate(key, input);
  }

  deactivate(issuer: Issuer): void {
    const key = this.insertOperation({
      kind: 'deactivate',
      label: issuer.display_name,
      issuerId: issuer.id,
      createInput: null
    });
    this.startDeactivate(key, issuer.id);
  }

  rotateKeys(issuer: Issuer): void {
    const key = this.insertOperation({
      kind: 'rotate_keys',
      label: issuer.display_name,
      issuerId: issuer.id,
      createInput: null
    });
    this.startRotateKeys(key, issuer.id);
  }

  retry(key: string): void {
    const op = this.find(key);
    if (!op) {
      return;
    }
    this.patch(key, { status: 'in_progress', error: null, taskId: null });
    if (op.kind === 'create' && op.createInput) {
      this.startCreate(key, op.createInput);
    } else if (op.kind === 'deactivate' && op.issuerId) {
      this.startDeactivate(key, op.issuerId);
    } else if (op.kind === 'rotate_keys' && op.issuerId) {
      this.startRotateKeys(key, op.issuerId);
    }
  }

  dismiss(key: string): void {
    this.stopPoll(key);
    this.removeOperation(key);
  }

  private startCreate(key: string, input: CreateIssuerRequest): void {
    this.service.create(input).subscribe({
      next: ({ task_id, issuer_id }) => {
        this.patch(key, { taskId: task_id, issuerId: issuer_id });
        this.poll(key, task_id);
      },
      error: () =>
        this.markFailed(key, this.t('issuer.operation.error_create_request'))
    });
  }

  private startDeactivate(key: string, issuerId: string): void {
    this.service.deactivate(issuerId).subscribe({
      next: ({ task_id }) => {
        if (task_id) {
          this.patch(key, { taskId: task_id });
          this.poll(key, task_id);
        } else {
          // Already deactivated server-side; no task to wait on.
          this.finishSuccess(key);
        }
      },
      error: () =>
        this.markFailed(
          key,
          this.t('issuer.operation.error_deactivate_request')
        )
    });
  }

  private startRotateKeys(key: string, issuerId: string): void {
    this.service.rotateKeys(issuerId).subscribe({
      next: ({ task_id }) => {
        this.patch(key, { taskId: task_id });
        this.poll(key, task_id);
      },
      error: () =>
        this.markFailed(key, this.t('issuer.operation.error_rotate_request'))
    });
  }

  private poll(key: string, taskId: string): void {
    let settled = false;
    const settle = (action: () => void) => {
      if (!settled) {
        settled = true;
        action();
      }
      this.stopPoll(key);
    };

    const sub = pollOperationTask(this.service, taskId).subscribe({
      next: (task) => {
        if (task.state === 'completed') {
          settle(() => this.finishSuccess(key));
        } else if (task.state === 'failed') {
          const message =
            task.error_message ?? this.t('issuer.operation.error_generic');
          settle(() => this.markFailed(key, message));
        }
      },
      error: () =>
        settle(() =>
          this.markFailed(key, this.t('issuer.operation.error_polling'))
        ),
      complete: () =>
        settle(() =>
          this.markFailed(key, this.t('issuer.operation.error_timeout'))
        )
    });

    this.polls.set(key, sub);
  }

  private finishSuccess(key: string): void {
    const op = this.find(key);
    if (!op || !op.issuerId) {
      return;
    }
    // The DID and canonical state only exist server-side, so re-fetch rather
    // than promote any optimistic data.
    this.service.get(op.issuerId).subscribe({
      next: (issuer) => {
        this.upsertIssuer(issuer);
        this.removeOperation(key);
        this.messages.add({
          severity: 'success',
          summary: this.t(SUCCESS_TOAST_KEYS[op.kind], {
            name: issuer.display_name
          })
        });
      },
      error: () => this.markFailed(key, this.t('issuer.operation.error_fetch'))
    });
  }

  private insertOperation(
    fields: Pick<
      TrackedOperation,
      'kind' | 'label' | 'issuerId' | 'createInput'
    >
  ): string {
    const key = crypto.randomUUID();
    this.trackedOperations.update((rows) => [
      { key, status: 'in_progress', error: null, taskId: null, ...fields },
      ...rows
    ]);
    return key;
  }

  private markFailed(key: string, error: string): void {
    this.patch(key, { status: 'failed', error });
  }

  private patch(key: string, change: Partial<TrackedOperation>): void {
    this.trackedOperations.update((rows) =>
      rows.map((r) => (r.key === key ? { ...r, ...change } : r))
    );
  }

  private removeOperation(key: string): void {
    this.trackedOperations.update((rows) => rows.filter((r) => r.key !== key));
  }

  private find(key: string): TrackedOperation | undefined {
    return this.trackedOperations().find((r) => r.key === key);
  }

  private stopPoll(key: string): void {
    this.polls.get(key)?.unsubscribe();
    this.polls.delete(key);
  }

  private t(key: string, params?: Record<string, unknown>): string {
    return this.transloco.translate(key, params);
  }
}
