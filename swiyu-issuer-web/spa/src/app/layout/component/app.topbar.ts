import { Component, OnInit, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { StyleClassModule } from 'primeng/styleclass';
import { AppConfigurator } from './app.configurator';
import { LayoutService } from '@/app/layout/service/layout.service';
import { Me, MeService } from '@/app/core/me-service';

@Component({
  selector: 'app-topbar',
  standalone: true,
  imports: [RouterModule, CommonModule, StyleClassModule, AppConfigurator],
  template: `<div class="layout-topbar">
    <div class="layout-topbar-logo-container">
      <button class="layout-menu-button layout-topbar-action" (click)="layoutService.onMenuToggle()">
        <i class="pi pi-bars"></i>
      </button>
      <a class="layout-topbar-logo" routerLink="/">
        <i class="pi pi-id-card text-primary" style="font-size: 1.5rem"></i>
        <span>swiyu issuer</span>
      </a>
    </div>

    <div class="layout-topbar-actions">
      @if (me(); as user) {
        <span class="layout-topbar-user hidden md:inline-block">{{ user.id }} &#64; {{ user.tenant_name }}</span>
      }

      <div class="layout-config-menu">
        <button type="button" class="layout-topbar-action" (click)="toggleDarkMode()">
          <i [ngClass]="{ 'pi ': true, 'pi-moon': layoutService.isDarkTheme(), 'pi-sun': !layoutService.isDarkTheme() }"></i>
        </button>
        <div class="relative">
          <button
            class="layout-topbar-action layout-topbar-action-highlight"
            pStyleClass="@next"
            enterFromClass="hidden"
            enterActiveClass="animate-scalein"
            leaveToClass="hidden"
            leaveActiveClass="animate-fadeout"
            [hideOnOutsideClick]="true"
          >
            <i class="pi pi-palette"></i>
          </button>
          <app-configurator />
        </div>
      </div>
    </div>
  </div>`
})
export class AppTopbar implements OnInit {
  layoutService = inject(LayoutService);
  private readonly meService = inject(MeService);

  protected readonly me = signal<Me | null>(null);

  ngOnInit(): void {
    this.meService.get().subscribe({
      next: (me) => this.me.set(me),
      error: () => this.me.set(null)
    });
  }

  toggleDarkMode() {
    this.layoutService.layoutConfig.update((state) => ({
      ...state,
      darkTheme: !state.darkTheme
    }));
  }
}
