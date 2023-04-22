import { defineConfig } from 'tsup';

export default defineConfig(() => {
  return {
    entry: ['lib/jsforce.js'],
    target: ['node16', 'es2020'],
    format: 'cjs',
    clean: false,
    sourcemap: false,
    splitting: false,
    dts: false,
  };
});
