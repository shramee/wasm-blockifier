# Blockifier in WASM

Introduces JS provider to interact with your contracts (or Dojo worlds) in a WASM package.

Loads contracts and executes them in locally in blockifier updating local state instantaneously.

## 🚴 Usage

Install [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) for building/testing.

### Build with `wasm-pack build`

```
wasm-pack build
```

### Test in Headless Browsers with `wasm-pack test`

```
wasm-pack test --headless --firefox
```
