import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { MenuItem } from 'primeng/api';
import { AppMenuitem } from './app.menuitem';

@Component({
  selector: 'app-menu',
  standalone: true,
  imports: [CommonModule, AppMenuitem, RouterModule],
  template: `<ul class="layout-menu">
    @for (item of model; track item.label) {
      @if (!item.separator) {
        <li app-menuitem [item]="item" [root]="true"></li>
      } @else {
        <li class="menu-separator"></li>
      }
    }
  </ul>`
})
export class AppMenu {
  model: MenuItem[] = [
    {
      label: 'swiyu issuer',
      items: [
        { label: 'Issuers', icon: 'pi pi-fw pi-id-card', routerLink: ['/issuers'] },
        {
          label: 'Credential Offers',
          icon: 'pi pi-fw pi-send',
          routerLink: ['/credential-offers']
        }
      ]
    }
  ];
}
