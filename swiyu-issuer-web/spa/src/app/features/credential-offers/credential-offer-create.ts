import { Component, computed, effect, inject, signal, untracked } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { TranslocoPipe, TranslocoService } from '@jsverse/transloco';
import { MessageService } from 'primeng/api';
import { ButtonModule } from 'primeng/button';
import { CardModule } from 'primeng/card';
import { InputNumberModule } from 'primeng/inputnumber';
import { MessageModule } from 'primeng/message';
import { ProgressSpinnerModule } from 'primeng/progressspinner';
import { SelectModule } from 'primeng/select';

import { JsonEditor, JsonEditorError } from '../../shared/json-editor/json-editor';
import { QrCode } from '../../shared/qr-code/qr-code';
import { IssuersStore } from '../issuers/issuers-store';
import { buildClaimSkeleton } from './claim-skeleton';
import { CreateCredentialOfferResult, CredentialOffersService } from './credential-offers-service';
import { CredentialTypesStore } from './credential-types-store';

const DEFAULT_EXPIRES_IN_SECONDS = 600;
const MIN_EXPIRES_IN_SECONDS = 60;
const MAX_EXPIRES_IN_SECONDS = 3600;

type WizardStep = 1 | 2 | 3;

@Component({
  selector: 'app-credential-offer-create',
  standalone: true,
  imports: [
    FormsModule,
    TranslocoPipe,
    ButtonModule,
    CardModule,
    InputNumberModule,
    MessageModule,
    ProgressSpinnerModule,
    SelectModule,
    JsonEditor,
    QrCode,
  ],
  templateUrl: './credential-offer-create.html',
  styleUrl: './credential-offer-create.scss',
})
export class CredentialOfferCreate {
  private readonly issuersStore = inject(IssuersStore);
  private readonly typesStore = inject(CredentialTypesStore);
  private readonly offersService = inject(CredentialOffersService);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly transloco = inject(TranslocoService);
  private readonly messages = inject(MessageService);

  protected readonly minExpires = MIN_EXPIRES_IN_SECONDS;
  protected readonly maxExpires = MAX_EXPIRES_IN_SECONDS;

  protected readonly step = signal<WizardStep>(1);

  protected readonly selectedIssuerId = signal<string | null>(null);
  protected readonly selectedTypeId = signal<string | null>(null);
  protected readonly claims = signal<string>('');
  protected readonly claimsValid = signal<boolean>(true);
  protected readonly claimsErrors = signal<JsonEditorError[]>([]);
  protected readonly expiresInSeconds = signal<number>(DEFAULT_EXPIRES_IN_SECONDS);

  protected readonly submitting = signal<boolean>(false);
  protected readonly submitError = signal<string | null>(null);
  protected readonly result = signal<CreateCredentialOfferResult | null>(null);

  protected readonly issuers = this.issuersStore.issuers;
  protected readonly issuersLoading = this.issuersStore.listLoading;

  protected readonly types = this.typesStore.types;
  protected readonly typesLoading = this.typesStore.typesLoading;
  protected readonly typesError = this.typesStore.typesError;

  protected readonly schema = this.typesStore.schema;
  protected readonly schemaLoading = this.typesStore.schemaLoading;
  protected readonly schemaError = this.typesStore.schemaError;

  protected readonly canAdvanceToEdit = computed(
    () => !!this.selectedIssuerId() && !!this.selectedTypeId(),
  );
  protected readonly canSubmit = computed(
    () => this.claimsValid() && !this.submitting() && !!this.schema(),
  );

  // Tracks which type the editor was last seeded for, so re-entering step 2
  // does not overwrite the operator's edits, but switching types re-seeds.
  private seededForType: string | null = null;

  constructor() {
    this.issuersStore.load();

    const preselectedIssuer = this.route.snapshot.queryParamMap.get('issuerId');
    if (preselectedIssuer) {
      this.selectedIssuerId.set(preselectedIssuer);
    }

    // Load the type list for the chosen issuer and reset any prior type pick.
    effect(() => {
      const issuerId = this.selectedIssuerId();
      untracked(() => {
        this.selectedTypeId.set(null);
        if (issuerId) {
          this.typesStore.loadTypesFor(issuerId);
        } else {
          this.typesStore.clearTypes();
        }
      });
    });

    // If the issuer has exactly one credential type, adopt it as the
    // selection (mirrors the single-issuer auto-select on the offers list).
    effect(() => {
      const types = this.types();
      if (types.length !== 1) {
        return;
      }
      untracked(() => {
        if (this.selectedTypeId() === null) {
          this.selectedTypeId.set(types[0].credential_type_id);
        }
      });
    });

    // Seed the editor from the schema once it arrives for the selected type.
    effect(() => {
      const schema = this.schema();
      if (!schema) {
        return;
      }
      const typeId = untracked(() => this.selectedTypeId());
      if (this.seededForType === typeId) {
        return;
      }
      untracked(() => {
        this.claims.set(JSON.stringify(buildClaimSkeleton(schema), null, 2));
        this.seededForType = typeId;
      });
    });
  }

  protected goToEdit(): void {
    const typeId = this.selectedTypeId();
    if (!this.selectedIssuerId() || !typeId) {
      return;
    }
    this.seededForType = null;
    this.typesStore.loadSchema(typeId);
    this.step.set(2);
  }

  protected backToSelect(): void {
    this.step.set(1);
  }

  protected submit(): void {
    const issuerId = this.selectedIssuerId();
    const typeId = this.selectedTypeId();
    if (!issuerId || !typeId || !this.canSubmit()) {
      return;
    }

    let parsedClaims: Record<string, unknown>;
    try {
      parsedClaims = JSON.parse(this.claims());
    } catch {
      this.submitError.set(this.transloco.translate('credential_offer.create.submit_error'));
      return;
    }

    this.submitting.set(true);
    this.submitError.set(null);
    this.offersService
      .create(issuerId, {
        credential_type_id: typeId,
        claims: parsedClaims,
        expires_in_seconds: this.expiresInSeconds(),
      })
      .subscribe({
        next: (result) => {
          this.result.set(result);
          this.submitting.set(false);
          this.step.set(3);
        },
        error: () => {
          this.submitError.set(this.transloco.translate('credential_offer.create.submit_error'));
          this.submitting.set(false);
        },
      });
  }

  protected copy(value: string): void {
    navigator.clipboard.writeText(value).then(
      () =>
        this.messages.add({
          severity: 'success',
          detail: this.transloco.translate('credential_offer.create.copied'),
        }),
      () =>
        this.messages.add({
          severity: 'error',
          detail: this.transloco.translate('credential_offer.create.copy_failed'),
        }),
    );
  }

  protected createAnother(): void {
    // Keep the issuer; reset everything downstream for a fresh offer.
    this.selectedTypeId.set(null);
    this.claims.set('');
    this.claimsValid.set(true);
    this.expiresInSeconds.set(DEFAULT_EXPIRES_IN_SECONDS);
    this.result.set(null);
    this.submitError.set(null);
    this.seededForType = null;
    this.typesStore.clearSchema();
    this.step.set(1);
  }

  protected backToOffers(): void {
    const issuerId = this.selectedIssuerId();
    this.router.navigate(['/credential-offers'], {
      queryParams: issuerId ? { issuerId } : {},
    });
  }
}
