// Test-only: makes the agent's config handshake deliver use_modern=true, as `--modern`
// does. Import AFTER agent/shared/frida-test-stubs.ts and BEFORE the agent entry
// (fritap_agent.ts reads the config once, while it loads).

const G = globalThis as any;

G.recv = (channel: string, onMessage: (value: any) => void) => {
    if (channel === "config_batch") onMessage({ payload: { use_modern: true } });
    return { wait: () => {} };
};
