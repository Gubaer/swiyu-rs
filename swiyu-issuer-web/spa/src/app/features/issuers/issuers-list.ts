import { Component, OnInit, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslocoPipe, TranslocoService } from '@jsverse/transloco';
import { MenuItem } from 'primeng/api';
import { TableModule } from 'primeng/table';
import { TagModule } from 'primeng/tag';
import { MessageModule } from 'primeng/message';
import { ButtonModule } from 'primeng/button';
import { MenuModule } from 'primeng/menu';
import { TabsModule } from 'primeng/tabs';
import { BadgeModule } from 'primeng/badge';

import { IssuersStore } from './issuers-store';

@Component({
  selector: 'app-issuers-list',
  imports: [
    RouterLink,
    TranslocoPipe,
    TableModule,
    TagModule,
    MessageModule,
    ButtonModule,
    MenuModule,
    TabsModule,
    BadgeModule
  ],
  templateUrl: './issuers-list.html',
  styleUrl: './issuers-list.scss'
})
export class IssuersList implements OnInit {
  private readonly store = inject(IssuersStore);
  private readonly transloco = inject(TranslocoService);

  protected readonly issuers = this.store.issuers;
  protected readonly creations = this.store.creations;
  protected readonly inProgressCount = this.store.inProgressCount;
  protected readonly loading = this.store.listLoading;
  protected readonly error = this.store.listError;

  // Built in TS, so the transloco pipe can't reach it; selectTranslate keeps
  // the label correct and re-emits on language change.
  protected actions: MenuItem[] = [];

  ngOnInit(): void {
    this.store.load();
    this.transloco
      .selectTranslate('issuer.list.new_menu_item')
      .subscribe((label) => {
        this.actions = [
          { label, icon: 'pi pi-plus', routerLink: '/issuers/create' }
        ];
      });
  }

  protected retry(key: string): void {
    this.store.retry(key);
  }

  protected dismiss(key: string): void {
    this.store.dismiss(key);
  }
}
