import { Component, OnInit, inject, signal } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { TranslocoService, TranslocoPipe } from '@jsverse/transloco';
import { ConfirmationService } from 'primeng/api';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { ConfirmDialogModule } from 'primeng/confirmdialog';
import { MessageModule } from 'primeng/message';
import { TagModule } from 'primeng/tag';

import { Issuer, IssuersService } from './issuers-service';
import { IssuersStore } from './issuers-store';

@Component({
  selector: 'app-issuer-detail',
  imports: [
    RouterLink,
    TranslocoPipe,
    ButtonModule,
    CardModule,
    ConfirmDialogModule,
    MessageModule,
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

  ngOnInit(): void {
    const id = this.route.snapshot.paramMap.get('id');
    if (!id) {
      this.error.set('issuer.detail.load_error');
      this.loading.set(false);
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

  private t(key: string, params?: Record<string, unknown>): string {
    return this.transloco.translate(key, params);
  }
}
