/**
 * Protocol barrel file.
 *
 * Re-exports all protocol classes and provides a lookup helper.
 */

export { Protocol, KeyMaterial } from "./base.js";
export { TLSProtocol } from "./tls.js";
export { IPSecProtocol } from "./ipsec.js";
export { SSHProtocol } from "./ssh.js";

import { Protocol } from "./base.js";
import { TLSProtocol } from "./tls.js";
import { IPSecProtocol } from "./ipsec.js";
import { SSHProtocol } from "./ssh.js";

const _protocols: { [name: string]: Protocol } = {
    tls: new TLSProtocol(),
    ipsec: new IPSecProtocol(),
    ssh: new SSHProtocol(),
};

/**
 * Get a protocol handler by name.
 * Returns undefined for unknown names or "auto".
 */
export function getProtocol(name: string): Protocol | undefined {
    return _protocols[name];
}
