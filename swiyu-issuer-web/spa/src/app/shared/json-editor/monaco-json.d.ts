// monaco 0.55 ships no per-module types for the JSON language contribution
// (its monaco.contribution.d.ts is `export {}`), even though the runtime module
// exports `jsonDefaults`. Declare the slice of that API we actually use.
declare module 'monaco-editor/esm/vs/language/json/monaco.contribution.js' {
  export interface DiagnosticsOptions {
    validate?: boolean;
    enableSchemaRequest?: boolean;
    schemaValidation?: 'error' | 'warning' | 'ignore';
    schemas?: { uri: string; fileMatch?: string[]; schema?: unknown }[];
  }

  export const jsonDefaults: {
    setDiagnosticsOptions(options: DiagnosticsOptions): void;
  };
}
