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
        loadComponent: () => import('./features/issuers/issuers-list').then((m) => m.IssuersList),
      },
      {
        path: 'issuers/create',
        loadComponent: () => import('./features/issuers/issuer-create').then((m) => m.IssuerCreate),
      },
      {
        path: 'issuers/:id',
        loadComponent: () => import('./features/issuers/issuer-detail').then((m) => m.IssuerDetail),
      },
      {
        path: 'credential-offers',
        loadComponent: () =>
          import('./features/credential-offers/credential-offers-list').then(
            (m) => m.CredentialOffersList,
          ),
      },
      {
        path: 'credential-offers/new',
        loadComponent: () =>
          import('./features/credential-offers/credential-offer-create').then(
            (m) => m.CredentialOfferCreate,
          ),
      },
    ],
  },
];
