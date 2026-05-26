import { Component, OnInit, inject, signal } from '@angular/core';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { MessageModule } from 'primeng/message';
import { TagModule } from 'primeng/tag';

import { Issuer, IssuersService } from './issuers-service';

@Component({
  selector: 'app-issuer-detail',
  imports: [
    RouterLink,
    TranslocoPipe,
    ButtonModule,
    CardModule,
    MessageModule,
    TagModule
  ],
  templateUrl: './issuer-detail.html',
  styleUrl: './issuer-detail.scss'
})
export class IssuerDetail implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly service = inject(IssuersService);

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
}
