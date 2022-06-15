/* In this file we store global variables and structures */


export var module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> } = {}


export const AF_INET = 2
export const AF_INET6 = 10
export const pointerSize = Process.pointerSize;