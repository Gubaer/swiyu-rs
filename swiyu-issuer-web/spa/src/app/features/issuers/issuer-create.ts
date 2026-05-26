import { Component, inject } from '@angular/core';
import {
  AbstractControl,
  FormBuilder,
  ReactiveFormsModule,
  ValidationErrors
} from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { TranslocoPipe } from '@jsverse/transloco';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { InputTextModule } from 'primeng/inputtext';
import { TextareaModule } from 'primeng/textarea';

import { IssuersStore } from './issuers-store';

// Treats a whitespace-only value as blank, which `Validators.required` does not.
function notBlank(control: AbstractControl): ValidationErrors | null {
  return control.value.trim().length === 0 ? { notBlank: true } : null;
}

@Component({
  selector: 'app-issuer-create',
  imports: [
    ReactiveFormsModule,
    RouterLink,
    TranslocoPipe,
    ButtonModule,
    CardModule,
    InputTextModule,
    TextareaModule
  ],
  templateUrl: './issuer-create.html',
  styleUrl: './issuer-create.scss'
})
export class IssuerCreate {
  private readonly fb = inject(FormBuilder);
  private readonly router = inject(Router);
  private readonly store = inject(IssuersStore);

  protected readonly form = this.fb.nonNullable.group({
    display_name: ['', notBlank],
    description: ''
  });

  protected onSubmit(): void {
    if (this.form.invalid) {
      return;
    }
    // The store inserts an optimistic "in progress" row and polls the saga;
    // we return to the list immediately so the user sees it appear.
    const { display_name, description } = this.form.getRawValue();
    this.store.create({
      display_name: display_name.trim(),
      description: description.trim()
    });
    this.router.navigate(['/issuers']);
  }
}
