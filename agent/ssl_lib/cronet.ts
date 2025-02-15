import { get_hex_string_from_byte_array, readAddresses } from "../shared/shared_functions.js";
import { devlog } from "../util/log.js";




export class Cronet {
    

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
        const MAX_KEY_LENGTH = 64;
        const RANDOM_KEY_LENGTH = 32;

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
            let KEY_LENGTH = 0;
            let calculatedKeyLength = 0;

            // Iterate through the memory to determine key length
            while (calculatedKeyLength < MAX_KEY_LENGTH) {
                //@ts-ignore
                const byte = Memory.readU8(keyPtr.add(calculatedKeyLength)); // Read one byte at a time


                if (byte === 0) { // Stop if null terminator is found (optional, adjust as needed)
                    if(calculatedKeyLength < 20){
                        calculatedKeyLength++;
                        continue;
                    }
                    break;
                }
                calculatedKeyLength++;
            }

            if (calculatedKeyLength > 24 && calculatedKeyLength <= 40) {
                KEY_LENGTH = 32; // Closest match is 32 bytes
            } else if (calculatedKeyLength >= 46 && calculatedKeyLength <=49) {
                KEY_LENGTH = 48; // Closest match is 48 bytes
            }else{
                KEY_LENGTH = 32; // fall back size
            }

            //@ts-ignore
            const keyData = Memory.readByteArray(keyPtr, KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
            
            // Convert the byte array to a string of  hex values
            const hexKey = get_hex_string_from_byte_array(keyData);
    
            secret_key = hexKey;
        } else {
            devlog("[Error] Argument 'key' is NULL");
        }

        //devlog("invoking ssl_log_secret() from BoringSSL statically linked into Cronet");
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