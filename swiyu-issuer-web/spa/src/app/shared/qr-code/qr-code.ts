import { Component, ElementRef, effect, input, viewChild } from '@angular/core';
import QRCode from 'qrcode';

// Renders a value as a scannable QR code, as inline SVG (crisp at any size,
// styleable, printable). Thin wrapper over the framework-agnostic `qrcode`
// package — value in, nothing out.
@Component({
  selector: 'app-qr-code',
  standalone: true,
  template: `<div #host class="qr-host" role="img" [attr.aria-label]="ariaLabel()"></div>`,
  styles: [
    `
      .qr-host {
        display: inline-block;
        line-height: 0;
      }
      .qr-host ::ng-deep svg {
        width: 100%;
        height: auto;
        max-width: 16rem;
      }
    `,
  ],
})
export class QrCode {
  readonly value = input.required<string>();
  readonly ariaLabel = input<string>('QR code');

  private readonly host = viewChild.required<ElementRef<HTMLElement>>('host');

  constructor() {
    effect(() => {
      const value = this.value();
      const element = this.host().nativeElement;
      QRCode.toString(value, { type: 'svg', margin: 1, errorCorrectionLevel: 'M' })
        .then((svg) => {
          element.innerHTML = svg;
        })
        .catch(() => {
          element.textContent = '';
        });
    });
  }
}
