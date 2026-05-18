import { Routes } from '@angular/router';
import { AppLayout } from './layout/component/app.layout';

export const routes: Routes = [
  {
    path: '',
    component: AppLayout,
    children: [
      { path: '', pathMatch: 'full', redirectTo: 'issuers' },
      {
        path: 'issuers',
        loadComponent: () =>
          import('./features/issuers/issuers-list').then((m) => m.IssuersList)
      }
    ]
  }
];
