import { readAddresses, checkNumberOfExports, resolveOffsets, toHexString } from "../../shared/shared_functions.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { devlog, log } from "../../util/log.js";



export class RusTLS {
    

    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    is_base_hook: boolean;

    static rustls_client_config_builder_new: any;
    static rustls_client_config_builder_new_custom: any;
    static rustls_client_config_set_key_log: any;

    // Callbackfuntion for logging keying material
    static keyLogCB = new NativeCallback (function(label: [NativePointer, UInt64], client_random: NativePointer, client_random_len: UInt64 , secret: NativePointer, secret_size:UInt64) {
        devlog("invoking keyLogCB from rustls");
        var labelStr: string;

        // If no label is provided the keyLog should begin with "CLIENT_RANDOM "
        if (label[1].toNumber() == 0) {
            labelStr = "CLIENT_RANDOM ";
        } else {
            labelStr = label[0].readUtf8String(label[1].toNumber());
        }

        // Read the client random and secrets as strings
        var clientRandomStr = client_random.readByteArray(client_random_len.toNumber());
        var secretStr = secret.readByteArray(secret_size.toNumber());


        // Convert byte arrays to hex strings for better logging
        var clientRandomHex = toHexString(clientRandomStr);
        var secretHex = toHexString(secretStr);

        // Construct the keylog message
        sendKeylog(`${labelStr} ${clientRandomHex} ${secretHex}`);

        return 1;
    }, 'void', [['pointer', 'size_t'], 'pointer', 'size_t', 'pointer', 'size_t']);


    constructor(public moduleName:string, public socket_library:String,is_base_hook: boolean ,public passed_library_method_mapping?: { [key: string]: Array<string> } ){
        this.module_name = moduleName;
        this.is_base_hook = is_base_hook;

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            if(checkNumberOfExports(moduleName) > 2 ){
                try {
                    this.library_method_mapping[`*${moduleName}*`] = ["*derive_logged_secret*", "*for_secret*"]
                }catch(e){
                    // right now do nothing
                }

                try {
                    this.library_method_mapping[`*${moduleName}*`] = ["*rustls_connection_write_tls*", "*rustls_connection_read_tls*", "*rustls_client_config_builder_new*", 
                "*rustls_client_config_builder_new_custom*", "*rustls_client_config_builder_set_key_log*"]
                }catch(e){
                    // right now do nothing
                }
            }
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }

        this.addresses = readAddresses(moduleName,this.library_method_mapping);
        this.module_name = moduleName;
        

        resolveOffsets(this.addresses, this.moduleName, socket_library, "rustls");
    }


    /*
    In Rustls the labels are mapped as enums
    cf. https://github.com/rustls/rustls/blob/5860d10317528e4f162db6e26c74f81575c51403/rustls/src/tls13/key_schedule.rs#L31
    */
    private enumMapping: { [key: number]: string } = {
        0: "RESUMPTION_PSK_BINDER_KEY",         // ResumptionPskBinderKey
        1: "CLIENT_EARLY_TRAFFIC_SECRET",        // ClientEarlyTrafficSecret
        2: "CLIENT_HANDSHAKE_TRAFFIC_SECRET",    // ClientHandshakeTrafficSecret
        3: "SERVER_HANDSHAKE_TRAFFIC_SECRET",    // ServerHandshakeTrafficSecret
        4: "CLIENT_TRAFFIC_SECRET_0",            // ClientApplicationTrafficSecret
        5: "SERVER_TRAFFIC_SECRET_0",            // ServerApplicationTrafficSecret
        6: "EXPORTER_SECRET",                    // ExporterMasterSecret
        7: "RESUMPTION_MASTER_SECRET",           // ResumptionMasterSecret
        8: "DERIVED"                           // Derived
    };
    
    getEnumString(enumValue: number): string | null {
        return this.enumMapping[enumValue] || null;
    }

    // Checks if the pointer's C-string starts with "key expansion" - only used for TLS 1.2 traffic
    isArgKeyExp(ptr: NativePointer): boolean {
        let labelStr = "";
        try {
            if (!ptr.isNull()) {
                const label: string = ptr.readCString() as string;
                labelStr = label;
                if (labelStr === null) {
                    return false;
                } else {
                    return labelStr.startsWith("key expansion");
                }
            }
        } catch (error) {
            devlog("[!] Error reading pointer in isArgKeyExp (RusTLS):"+ (error as Error).message);
            return false;
        }
            return false;
    }


    /**
     * Hooking hkdf_expand_label() to get secrets from TLS 1.3 traffic.
     * This is used for the Android Hooks only
     */
    /*
     Hooking hkdf_expand_label to get secrets from TLS 1.3 traffic. 
     This is used for the Android Hooks.
    */
    dumpKeysFromDeriveSecrets(
        client_random_ptr: NativePointer,
        key: NativePointer,
        key_len: number,
        label_enum: number
      ): boolean {
        let KEY_LENGTH = 32; // Default to 32 bytes.
        if (key_len > 16) {
          KEY_LENGTH = key_len;
        }
        let labelStr = "";
        let client_random = "";
        let secret_key = "";
        const RANDOM_KEY_LENGTH = 32;
    
        // Retrieve the descriptive label from the enum mapping.
        labelStr = this.getEnumString(label_enum) || "";
    
        if (client_random_ptr != null) {
            const randomData = client_random_ptr.readByteArray(RANDOM_KEY_LENGTH);
            if (randomData) {
                client_random = toHexString(randomData);
            }
        } else {
          //devlog("[Error] Argument 'client_random_ptr' is NULL");
          client_random = "<identify using PCAP> ";
        }

        if (!key.isNull()) {

            const keyData = key.readByteArray(KEY_LENGTH);
            if (keyData) {
                secret_key = toHexString(keyData);
            }
        } else {
            devlog("[Error] Argument 'key' is NULL");
        }
    
        sendKeylog(labelStr+" "+client_random+" "+secret_key);
        return true;
    }

    /**
     *  Hooking from_key_exchange() to get secrets from TLS 1.2 traffic
     *  https://github.com/rustls/rustls/blob/293f05e9d1011132a749b8b6e0435f701421fd01/rustls/src/tls12/mod.rs#L102
     *  This hook is used for both, Linux and Android.
     */

    dumpKeysFromPRF(
        client_random_ptr: NativePointer,
        key: NativePointer
      ): boolean {
        const KEY_LENGTH = 32;
        const MASTER_SECRET_LEN = 48;
        const labelStr = "CLIENT_RANDOM";
        let client_random = "";
        let secret_key = "";
        
        if (!key.isNull()) {
            const keyData = key.readByteArray(MASTER_SECRET_LEN);
            if (keyData) {
                secret_key = toHexString(keyData);
            }
        } else {
          devlog("[!] Argument 'key' is NULL");
        }

        if (!client_random_ptr.isNull()) {
            const keyData = client_random_ptr.readByteArray(KEY_LENGTH);
            if (keyData) {
                client_random = toHexString(keyData);
            }
        } else {
          devlog("[!] Argument 'client_random_ptr' is NULL");
        }
    

        sendKeylog(labelStr+" "+client_random+" "+secret_key);
        return true;
    }

    /**
     * On Linux the BoringSecretHunter Identifies a different function (derive_logged_secrets()).
     * https://github.com/rustls/rustls/blob/bdb303696dea02ecc6b5de3907880e181899d717/rustls/src/tls13/key_schedule.rs#L676
     * The following extracts the secrets for TLS 1.3.
     */
    dumpKeysFromDeriveLogged(
        client_random_ptr: NativePointer,
        key: NativePointer,
        label_enum: number
    ) {
        /* 
        key_len needs to be parsed from key
        key has the following structure: | key (length: key_size) | padding (length: 64 bytes - key_size) | key_size 
        */
        let KEY_LENGTH = (key.add(64)).readU32();
        let labelStr = "";
        let client_random = "";
        let secret_key = "";
        const RANDOM_KEY_LENGTH = 32;
        
        devlog("Called dumpKeysFromDeriveLogged()");

        // Retrieve the descriptive label from the enum mapping.
        labelStr = this.getEnumString(label_enum) || "";
    
        if (client_random_ptr != null) {
            const randomData = client_random_ptr.readByteArray(RANDOM_KEY_LENGTH);
            if (randomData) {
                client_random = toHexString(randomData);
            }
        } else {
          client_random = "<identify using PCAP> ";
        }

        if (!key.isNull()) {
            const keyData = key.readByteArray(KEY_LENGTH);
            if (keyData) {
                secret_key = toHexString(keyData);
            }
        } else {
            devlog("[Error] Argument 'key' is NULL");
        }
    
        sendKeylog(labelStr+" "+client_random+" "+secret_key);
        return true;
    }

    hook_tls_12_key_generation_function(){

    }


    install_plaintext_read_hook(){
        // TBD
    }

    install_plaintext_write_hook(){
        // TBD
    }

    install_key_extraction_hook(){
        // needs to be setup for the specific plattform
    }




    


}