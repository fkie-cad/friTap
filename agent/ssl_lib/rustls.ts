import { get_hex_string_from_byte_array, readAddresses } from "../shared/shared_functions.js";
import { devlog } from "../util/log.js";

export class Rustls {
    
    library_method_mapping: { [key: string]: Array<string> } =  {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer} };
    module_name: string;
    is_base_hook: boolean;
    client_random: NativePointer;
    secret_block: NativePointer;

    labels: string[] = [
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SEREVER_HANDSHAKE_TRAFFIC_SECRET"
    ];
    

    constructor (public moduleName: string, public socket_library: String, is_base_hook: boolean, public passed_libaray_method_mapping?: { [kes: string]: Array<string>}) {
        this.module_name = moduleName;
        this.is_base_hook = is_base_hook;

        if (typeof passed_libaray_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_libaray_method_mapping;
        } else {
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }

        this.addresses = readAddresses(moduleName, this.library_method_mapping);
    }

    switchEndian(hexStr: string): string {
        const pairs = hexStr.match(/.{2}/g);
        if (!pairs) return "";
        return pairs.reverse().join('');
    }
    
    getPattern(secret_size: number): string {
        const secretSizeHexBigEndian: string = secret_size.toString(16).padStart(16, "0");
        const secretSizeHexLittleEndian: string = this.switchEndian(secretSizeHexBigEndian);
        const zeroBytesHex: string = "00".repeat(64 - secret_size);
        return zeroBytesHex + secretSizeHexLittleEndian;
    }
    
    getPatternLength(secret_size: number): number {
        return (64 - secret_size) + 8;
    }
    

    dumpKeys_onEnter(randomPtr: NativePointer, okmBlockPtr: NativePointer): void {
        this.client_random = randomPtr;
        this.secret_block = okmBlockPtr;
    }

    
    dumpKeys_onLeave() {
        let offset_first_secret = 24;
        let offset_size_value = offset_first_secret + 64;
        //@ts-ignore
        let secret_size = Memory.readU64(this.secret_block.add(offset_size_value));
        let pattern = this.getPattern(secret_size);
        let pattern_length = this.getPatternLength(secret_size);
        let secret_index = 0;

        //@ts-ignore
        let client_random = Memory.readByteArray(this.client_random, 32);
        let client_random_str = get_hex_string_from_byte_array(client_random);


        // Iterate over first 1000 Bytes of Secret_Block
        // 8-byte alignment
        for (let i = 0; i < 1000 - pattern_length; i += 8) {
            //@ts-ignore
            let current_bytes = Memory.readByteArray(this.secret_block, pattern_length);
            let current = get_hex_string_from_byte_array(current_bytes);

            if (current === pattern && (i - secret_size) >= 0) {
                let secret_offset = i - secret_size;
                let secret_ptr = this.secret_block.add(secret_offset);
                //@ts-ignore
                let secret = Memory.readByteArray(secret_ptr, secret_size);
                let secret_str = get_hex_string_from_byte_array(secret);

                var message: { [key: string]: string | number | null} = {};
                message["contentType"] = "keylog";
                message["keylog"] = this.labels[secret_index] + " " + client_random_str + " " + secret;
                send(message);

                secret_index++;
            }
        }
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