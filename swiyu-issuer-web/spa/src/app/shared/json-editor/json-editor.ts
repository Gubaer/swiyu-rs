import {
  Component,
  ElementRef,
  OnDestroy,
  afterNextRender,
  effect,
  input,
  output,
  viewChild,
} from '@angular/core';

// Import only the editor API plus the JSON language contribution, not the full
// `monaco-editor` barrel — that keeps every other language (and its worker) out
// of the bundle.
import * as monaco from 'monaco-editor/esm/vs/editor/editor.api.js';
// Importing the JSON contribution registers the language and gives us
// `jsonDefaults`, the handle for live schema diagnostics. (In monaco 0.55 the
// old `monaco.languages.json` accessor is deprecated.)
import { jsonDefaults } from 'monaco-editor/esm/vs/language/json/monaco.contribution.js';

// Monaco resolves its workers through this global. The JSON language asks for
// the 'json' worker; everything else uses the core editor worker. The worker
// shims are bundled by esbuild via `new Worker(new URL(...))`.
const monacoEnvironment: monaco.Environment = {
  getWorker(_workerId, label) {
    if (label === 'json') {
      return new Worker(new URL('./json.worker', import.meta.url), { type: 'module' });
    }
    return new Worker(new URL('./editor.worker', import.meta.url), { type: 'module' });
  },
};
(globalThis as unknown as { MonacoEnvironment: monaco.Environment }).MonacoEnvironment =
  monacoEnvironment;

// A JSON Schema is just an opaque object as far as this component is concerned;
// Monaco's diagnostics API types the schema as `any`.
type JsonSchema = Record<string, unknown>;

// A single validation problem (JSON syntax or schema violation) surfaced from
// Monaco's markers, with its 1-based location so callers can list it.
export interface JsonEditorError {
  message: string;
  line: number;
  column: number;
}

const SCHEMA_URI = 'inmemory://json-editor/value.json';

// Thin standalone wrapper over Monaco for editing a single JSON document with
// live JSON-Schema validation. Generic and reusable — it knows nothing about
// credential offers.
@Component({
  selector: 'app-json-editor',
  standalone: true,
  template: `<div #host class="json-editor-host"></div>`,
  styles: [
    `
      .json-editor-host {
        display: block;
        width: 100%;
        height: 100%;
        min-height: 320px;
      }
    `,
  ],
})
export class JsonEditor implements OnDestroy {
  readonly value = input<string>('');
  readonly schema = input<JsonSchema | null>(null);
  readonly valueChange = output<string>();
  readonly validChange = output<boolean>();
  readonly errorsChange = output<JsonEditorError[]>();

  private readonly host = viewChild.required<ElementRef<HTMLElement>>('host');

  private editor?: monaco.editor.IStandaloneCodeEditor;
  private model?: monaco.editor.ITextModel;
  private disposables: monaco.IDisposable[] = [];

  constructor() {
    afterNextRender(() => this.createEditor());

    // Push the schema into Monaco's global JSON diagnostics whenever it changes.
    // Safe to call before the editor exists; diagnostics options are global.
    effect(() => this.applySchema(this.schema()));

    // Reflect external value changes back into the model without clobbering the
    // operator's cursor when the value already matches.
    effect(() => {
      const next = this.value();
      if (this.model && this.model.getValue() !== next) {
        this.model.setValue(next);
      }
    });
  }

  ngOnDestroy(): void {
    for (const disposable of this.disposables) {
      disposable.dispose();
    }
    this.model?.dispose();
    this.editor?.dispose();
  }

  private createEditor(): void {
    const model = monaco.editor.createModel(this.value(), 'json', monaco.Uri.parse(SCHEMA_URI));
    this.model = model;

    this.editor = monaco.editor.create(this.host().nativeElement, {
      model,
      automaticLayout: true,
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      tabSize: 2,
      fontSize: 13,
    });

    this.disposables.push(
      model.onDidChangeContent(() => this.valueChange.emit(model.getValue())),
      monaco.editor.onDidChangeMarkers(() => this.emitValidity()),
    );

    this.applySchema(this.schema());
    this.emitValidity();
  }

  private applySchema(schema: JsonSchema | null): void {
    jsonDefaults.setDiagnosticsOptions({
      validate: true,
      enableSchemaRequest: false,
      // Monaco reports schema violations as warnings by default; promote them
      // to errors so they show up alongside syntax errors and gate submit.
      schemaValidation: 'error',
      schemas: schema ? [{ uri: SCHEMA_URI, fileMatch: [SCHEMA_URI], schema }] : [],
    });
  }

  private emitValidity(): void {
    if (!this.model) {
      return;
    }
    const errors = monaco.editor
      .getModelMarkers({ resource: this.model.uri })
      .filter((marker) => marker.severity === monaco.MarkerSeverity.Error);
    this.validChange.emit(errors.length === 0);
    this.errorsChange.emit(
      errors.map((marker) => ({
        message: marker.message,
        line: marker.startLineNumber,
        column: marker.startColumn,
      })),
    );
  }
}
