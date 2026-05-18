import { Component, OnInit, inject, signal } from '@angular/core';
import { ToolbarModule } from 'primeng/toolbar';
import { ButtonModule } from 'primeng/button';
import { MenuModule } from 'primeng/menu';
import { MenuItem } from 'primeng/api';

import { Me, MeService } from '../core/me-service';

@Component({
  selector: 'app-top-bar',
  imports: [ToolbarModule, ButtonModule, MenuModule],
  templateUrl: './top-bar.html',
  styleUrl: './top-bar.scss'
})
export class TopBar implements OnInit {
  private readonly meService = inject(MeService);

  protected readonly me = signal<Me | null>(null);
  protected readonly userMenu: MenuItem[] = [
    { label: 'Logout (TODO)', icon: 'pi pi-sign-out', disabled: true }
  ];

  ngOnInit(): void {
    this.meService.get().subscribe({
      next: (me) => this.me.set(me),
      error: () => this.me.set(null)
    });
  }
}
