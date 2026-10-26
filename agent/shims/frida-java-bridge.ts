// Slim Wine bundle shim for frida-java-bridge (fkie-cad/friTap#52): the Wine
// watcher route never uses Java, and bundling the real bridge's bytes made
// early injection into a freshly-created Wine process unreliable. This empty
// stub is aliased in via tsconfig `paths` for the Wine bundle only; the main
// bundle keeps the real bridge for Android.
const stub: any = { available: false, perform: (_cb?: any) => {}, performNow: (_cb?: any) => {} };
export default stub;
