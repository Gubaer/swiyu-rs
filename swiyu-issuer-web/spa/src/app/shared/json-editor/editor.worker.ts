// Worker entry for Monaco's core editor worker. esbuild (the @angular/build
// builder) bundles this as a separate worker output when referenced via
// `new Worker(new URL('./editor.worker', import.meta.url), { type: 'module' })`.
import 'monaco-editor/esm/vs/editor/editor.worker.js';
