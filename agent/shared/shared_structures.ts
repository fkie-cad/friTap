/* In this file we store global variables and structures */

export type ModuleHookingType = (moduleName: string, is_base_hook: boolean) => void;
export var module_library_mapping:{ [key: string]: Array<[any, ModuleHookingType]> }  = {};


export const AF_INET = 2
export const AF_INET6 = 10
export const pointerSize = Process.pointerSize;