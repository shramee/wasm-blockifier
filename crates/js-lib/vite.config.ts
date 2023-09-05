import { resolve } from 'path'
import { defineConfig } from 'vite'
import dts from 'vite-plugin-dts'

export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'lib/main.ts'),
      name: 'Dojo',
      fileName: 'dojo'
    }
  },
  plugins: [
    dts(
      {
        insertTypesEntry: true,
      }
    )
  ]
})
