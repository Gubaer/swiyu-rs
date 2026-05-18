import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'issuers' },
  {
    path: 'issuers',
    loadComponent: () => import('./features/issuers/issuers-list').then((m) => m.IssuersList)
  }
];
