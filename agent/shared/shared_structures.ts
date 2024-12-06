/* In this file we store global variables and structures */

export type ModuleHookingType = (moduleName: string, is_base_hook: boolean) => void;
export var module_library_mapping:{ [key: string]: Array<[any, ModuleHookingType]> }  = {};

export const unwantedFDs = new Set<number>(); // this helps us to track if we alredy encountered this fd

export const AF_INET = 2;
export const AF_INET6 = 10;
export const AF_UNIX = 1;
export const pointerSize = Process.pointerSize;

export const AddressFamilyMapping: { [key: number]: string } = {
    2: "AF_INET", // IPv4
    10: "AF_INET6", // IPv6
    1: "AF_UNIX", // Unix domain sockets
    17: "AF_PACKET", // Raw packets
    // Add other address families as needed
};