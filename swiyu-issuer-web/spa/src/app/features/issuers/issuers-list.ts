import { Component, OnInit, inject, signal } from '@angular/core';
import { TableModule } from 'primeng/table';
import { TagModule } from 'primeng/tag';
import { MessageModule } from 'primeng/message';

import { Issuer, IssuersService } from './issuers-service';

@Component({
  selector: 'app-issuers-list',
  imports: [TableModule, TagModule, MessageModule],
  templateUrl: './issuers-list.html',
  styleUrl: './issuers-list.scss'
})
export class IssuersList implements OnInit {
  private readonly service = inject(IssuersService);

  protected readonly issuers = signal<Issuer[]>([]);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);

  ngOnInit(): void {
    this.service.list().subscribe({
      next: (resp) => {
        this.issuers.set(resp.items);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('Failed to load issuers from the BFF.');
        this.loading.set(false);
      }
    });
  }
}
