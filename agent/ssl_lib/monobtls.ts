import { get_hex_string_from_byte_array, readAddresses } from "../shared/shared_functions.js";
import { devlog } from "../util/log.js";




export class Mono_BTLS {
    

    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    is_base_hook: boolean;


    constructor(public moduleName:string, public socket_library:String,is_base_hook: boolean ,public passed_library_method_mapping?: { [key: string]: Array<string> } ){
        this.module_name = moduleName;
        this.is_base_hook = is_base_hook;

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }

        this.addresses = readAddresses(moduleName,this.library_method_mapping);
    }

    get_client_random(s3_ptr: NativePointer, SSL3_RANDOM_SIZE: number): string {
        if (!s3_ptr.isNull()) {
            const client_random_ptr: NativePointer = s3_ptr.add(0x30); // Offset in s3 struct
            //@ts-ignore
            const client_random = Memory.readByteArray(client_random_ptr, SSL3_RANDOM_SIZE);
            
            // Convert the byte array to a hex string
            const hexClientRandom = get_hex_string_from_byte_array(new Uint8Array(client_random as ArrayBuffer));
    
            return hexClientRandom;
        } else {
            devlog("[Error] s3 pointer is NULL");
            return "";
        }
    }
    
    get_client_random_from_ssl_struct(ssl_st_ptr: NativePointer): string {
        const SSL3_RANDOM_SIZE = 32;
        let offset_s3: number;
    
        switch (Process.arch) {
            case 'x64':
                offset_s3 = 0x30;
                break;
            case 'arm64':
                offset_s3 = 0x30;
                break;
            case 'ia32':
                offset_s3 = 0x2C;
                break;
            case 'arm':
                offset_s3 = 0x2C;
                break;
            default:
                devlog("[Error] Unsupported architecture");
                return "";
        }
    
        const s3_ptr = ssl_st_ptr.add(offset_s3).readPointer();
        return this.get_client_random(s3_ptr, SSL3_RANDOM_SIZE);
    }


    dumpKeys(labelPtr: NativePointer, sslStructPtr: NativePointer, keyPtr: NativePointer): void {
        const KEY_LENGTH = 32; // Assuming key length is 32 bytes

        let labelStr = '';
        let client_random = '';
        let secret_key = '';

        // Read the label (the label pointer might contain a C string)
        if (!labelPtr.isNull()) {
            labelStr = labelPtr.readCString() ?? '';  // Read label as a C string
            //devlog(`Label: ${labelStr}`);
        } else {
            devlog("[Error] Argument 'labelPtr' is NULL");
        }

        // Extract client_random from the SSL structure
        if (!sslStructPtr.isNull()) {
            client_random = this.get_client_random_from_ssl_struct(sslStructPtr)
        }else {
            devlog("[Error] Argument 'sslStructPtr' is NULL");
        }

        if (!keyPtr.isNull()) {
            //@ts-ignore
            const keyData = Memory.readByteArray(keyPtr, KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
            
            // Convert the byte array to a string of  hex values
            const hexKey = get_hex_string_from_byte_array(keyData);
    
            secret_key = hexKey;
        } else {
            devlog("[Error] Argument 'key' is NULL");
        }

        //devlog("invoking ssl_log_secret() from BoringSSL statically linked into Mono BTLS");
        var message: { [key: string]: string | number | null } = {}
        message["contentType"] = "keylog"
        message["keylog"] = labelStr+" "+client_random+" "+secret_key;
        send(message)
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