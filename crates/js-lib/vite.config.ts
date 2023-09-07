import { resolve } from 'path'
import { defineConfig } from 'vite'
import dts from 'vite-plugin-dts'
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'lib/main.ts'),
      name: 'Dojo',
      fileName: 'dojo'
    }
  },
  plugins: [
    wasm(),
    topLevelAwait(),
    dts(
      {
        insertTypesEntry: true,
      }
    )
  ]
})
