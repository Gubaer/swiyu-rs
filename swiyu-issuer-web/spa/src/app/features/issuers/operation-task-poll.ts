import { Observable, switchMap, take, takeWhile, timer } from 'rxjs';

import { IssuersService, OperationTask } from './issuers-service';

const POLL_INTERVAL_MS = 1500;
// ~2 minutes of polling before giving up on a stuck saga.
const MAX_POLLS = 80;

// Polls an operation task until it reaches a terminal state (completed/failed)
// or the poll budget runs out. The stream emits each task snapshot and then
// completes; subscribers track whether a terminal state was actually seen to
// distinguish completion from a timeout.
export function pollOperationTask(
  service: IssuersService,
  taskId: string
): Observable<OperationTask> {
  return timer(0, POLL_INTERVAL_MS).pipe(
    switchMap(() => service.getTask(taskId)),
    take(MAX_POLLS),
    takeWhile(
      (task) => task.state !== 'completed' && task.state !== 'failed',
      true
    )
  );
}
