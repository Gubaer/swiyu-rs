import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { TranslocoService, TranslocoPipe } from '@jsverse/transloco';
import hljs from 'highlight.js/lib/core';
import json from 'highlight.js/lib/languages/json';
import { ConfirmationService } from 'primeng/api';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { DialogModule } from 'primeng/dialog';
import { MessageModule } from 'primeng/message';
import { TableModule } from 'primeng/table';
import { TagModule } from 'primeng/tag';

import { DidLogEntry, Issuer, IssuersService } from './issuers-service';
import { IssuersStore } from './issuers-store';

hljs.registerLanguage('json', json);

@Component({
  selector: 'app-issuer-detail',
  imports: [
    RouterLink,
    TranslocoPipe,
    ButtonModule,
    CardModule,
    ConfirmDialogModule,
    DialogModule,
    MessageModule,
    TableModule,
    TagModule
  ],
  templateUrl: './issuer-detail.html',
  styleUrl: './issuer-detail.scss'
})
export class IssuerDetail implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly service = inject(IssuersService);
  private readonly store = inject(IssuersStore);
  private readonly confirmation = inject(ConfirmationService);
  private readonly transloco = inject(TranslocoService);

  protected readonly issuer = signal<Issuer | null>(null);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly didLog = signal<DidLogEntry[]>([]);
  protected readonly didLogLoading = signal(true);
  protected readonly didLogError = signal<string | null>(null);

  protected readonly selectedEntry = signal<DidLogEntry | null>(null);
  protected readonly entryDialogVisible = signal(false);
  protected readonly entryDialogHeader = computed(() => {
    const entry = this.selectedEntry();
    if (!entry) {
      return '';
    }
    return this.t('issuer.detail.did_log_entry_title', {
      version: entry.version ?? entry.versionId
    });
  });
  // Syntax-highlighted HTML for the selected entry. highlight.js escapes the
  // input, so the output is safe to bind via [innerHTML].
  protected readonly highlightedEntry = computed(() => {
    const entry = this.selectedEntry();
    if (!entry) {
      return '';
    }
    const text = JSON.stringify(entry.entry, null, 2);
    return hljs.highlight(text, { language: 'json' }).value;
  });

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (!id) {
      this.error.set('issuer.detail.load_error');
      this.loading.set(false);
      this.didLogLoading.set(false);
      return;
    }
    this.service.get(id).subscribe({
      next: (issuer) => {
        this.issuer.set(issuer);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('issuer.detail.load_error');
        this.loading.set(false);
      }
    });
    this.service.getDidLog(id).subscribe({
      next: (resp) => {
        this.didLog.set(resp.entries);
        this.didLogLoading.set(false);
      },
      error: () => {
        this.didLogError.set('issuer.detail.did_log_error');
        this.didLogLoading.set(false);
      }
    });
  }

  protected openEntry(entry: DidLogEntry): void {
    this.selectedEntry.set(entry);
    this.entryDialogVisible.set(true);
  }

  // A versionId is `<versionNumber>-<entryHash>`; return the entryHash part.
  protected entryHash(versionId: string): string {
    const dash = versionId.indexOf('-');
    return dash === -1 ? versionId : versionId.slice(dash + 1);
  }

  protected deactivate(): void {
    const issuer = this.issuer();
    if (!issuer || issuer.state !== 'active') {
      return;
    }
    this.confirmation.confirm({
      header: this.t('issuer.detail.deactivate_confirm_header'),
      message: this.t('issuer.detail.deactivate_confirm_message', {
        name: issuer.display_name
      }),
      icon: 'pi pi-exclamation-triangle',
      acceptButtonProps: {
        label: this.t('issuer.detail.deactivate_confirm_accept'),
        severity: 'danger'
      },
      rejectButtonProps: {
        label: this.t('issuer.detail.deactivate_confirm_reject'),
        severity: 'secondary',
        outlined: true
      },
      accept: () => {
        // The store tracks and polls the deactivation; it shows up in the
        // list's "In progress" tab. Return there so the user can follow it.
        this.store.deactivate(issuer);
        this.router.navigate(['/issuers']);
      }
    });
  }

  protected rotateKeys(): void {
    const issuer = this.issuer();
    if (!issuer || issuer.state !== 'active') {
      return;
    }
    this.confirmation.confirm({
      header: this.t('issuer.detail.rotate_confirm_header'),
      message: this.t('issuer.detail.rotate_confirm_message', {
        name: issuer.display_name
      }),
      icon: 'pi pi-exclamation-triangle',
      acceptButtonProps: {
        label: this.t('issuer.detail.rotate_confirm_accept')
      },
      rejectButtonProps: {
        label: this.t('issuer.detail.rotate_confirm_reject'),
        severity: 'secondary',
        outlined: true
      },
      accept: () => {
        // Tracked and polled by the store; visible in the "In progress" tab.
        this.store.rotateKeys(issuer);
        this.router.navigate(['/issuers']);
      }
    });
  }

  private t(key: string, params?: Record<string, unknown>): string {
    return this.transloco.translate(key, params);
  }
}
