import { readAddresses, getPortsAndAddresses, resolveOffsets } from "../../../shared/shared_functions.js";
import { sendDatalog } from "../../../shared/shared_structures.js";
import { enable_default_fd, pcap_enabled } from "../../../fritap_agent.js";
import { log } from "../../../util/log.js";
import { hookMatrixSslReads, hookMatrixSslWrites } from "../../../shared/matrixssl_plaintext.js";


export class matrix_SSL {



    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    /** Socket fd of the last successful connect() (install_helper_hook); -1 until then. */
    fd: number = -1;

    static matrixSslNewCLientSession: any;
    static sessionId: string;
    static matrixSslGetSid: any;


    constructor(public moduleName: string, public socket_library: String, public passed_library_method_mapping?: { [key: string]: Array<string> }) {
        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        } else {
            this.library_method_mapping[`*${moduleName}*`] = ["matrixSslReceivedData", "matrixSslProcessedData", "matrixSslGetWritebuf", "matrixSslGetSid", "matrixSslEncodeWritebuf"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl", "socket"];
        }

        this.addresses = readAddresses(moduleName,this.library_method_mapping);
        this.module_name = moduleName;

        resolveOffsets(this.addresses, this.moduleName, socket_library, "matrixssl");

        //Creates a new client session. If this happens we will save the id of this new session
        matrix_SSL.matrixSslNewCLientSession = new NativeFunction(this.addresses[this.moduleName]["matrixSslNewClientSession"], "int", ["pointer", "pointer", "pointer", "pointer", "int", "pointer", "pointer", "pointer", "pointer", "pointer"]);
        //This function extracts the sessionID object out of the ssl object
        matrix_SSL.matrixSslGetSid = new NativeFunction(this.addresses[this.moduleName]["matrixSslGetSid"], "pointer", ["pointer"]);
        
    }


    


    install_plaintext_read_hook() {
        if (!pcap_enabled) return;
        const moduleAddresses = this.addresses[this.moduleName];
        hookMatrixSslReads(moduleAddresses["matrixSslReceivedData"], moduleAddresses["matrixSslProcessedData"],
            (ssl, data, functionName) => this.emitRecord(true, ssl, data, functionName));
    }

    install_plaintext_write_hook() {
        if (!pcap_enabled) return;
        const moduleAddresses = this.addresses[this.moduleName];
        hookMatrixSslWrites(moduleAddresses["matrixSslGetWritebuf"], moduleAddresses["matrixSslEncodeWritebuf"],
            (ssl, data, functionName) => this.emitRecord(false, ssl, data, functionName));
    }

    /** Send one plaintext record, attributed to the fd of the last successful connect(). */
    private emitRecord(isRead: boolean, ssl: NativePointer, data: ArrayBuffer, functionName: string): void {
        const message = getPortsAndAddresses(this.fd, isRead, this.addresses[this.module_name], enable_default_fd);
        if (message === null) return;
        message["ssl_session_id"] = this.sessionIdFor(ssl);
        message["function"] = functionName;
        sendDatalog(message, data);
    }


    install_tls_keys_callback_hook() {
        // TBD
    }

    install_helper_hook(){
        const self = this;
    
        Interceptor.attach(this.addresses[this.moduleName]["matrixSslNewSessionId"], {
            onEnter: function (args) {
                this.sslSessionPointer = args[0];
            },
            onLeave: function (retval: any) {
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return
                }

                var sessionIdLength = this.sslSessionPointer.add(2 * Process.pointerSize).readU32();
                matrix_SSL.sessionId = this.sslSessionPointer.add(Process.pointerSize).readPointer().readCString(sessionIdLength);                
            }

        });

        Interceptor.attach(this.addresses[this.moduleName]["connect"], {
            onEnter: function (args) {
                this.sockfd = args[0].toInt32();
            },
            onLeave: function (retval: any) {
                // connect() returns 0 on success; the fd is its first argument.
                if (retval.toInt32() !== 0) {
                    return
                }

                self.fd = this.sockfd;
            }
        })
    }

    /** Session id from matrixSslGetSid when resolved, else the one install_helper_hook saved. */
    sessionIdFor(ssl: any): string {
        return this.addresses[this.moduleName]["matrixSslGetSid"] === undefined ? matrix_SSL.sessionId : this.getSessionId(ssl);
    }

    getSessionId(ssl: any){
        const sid = matrix_SSL.matrixSslGetSid(ssl);
        const sessionIdLength = sid.add(2 * Process.pointerSize).readU32();
        const sessionId = sid.add(Process.pointerSize).readPointer().readCString(sessionIdLength);
        return sessionId;
    }


}

