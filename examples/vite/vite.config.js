import wasm from "vite-plugin-wasm";
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [
   wasm(),
  ],
  optimizeDeps: {
    esbuildOptions: {
      target: 'esnext'
    }
  },
  build: {
    target: 'esnext'
  },
});
