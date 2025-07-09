import { devlog, log } from "./log.js";

// Go runtime structure parsing for function discovery
// This module parses Go runtime internal structures to find function addresses
// even when symbols are not exported or are obfuscated

interface GoFunction {
    name: string;
    address: NativePointer;
    endAddress?: NativePointer;
    size?: number;
}

// Enhanced magic numbers from go_parser research
const GO_MAGIC_NUMBERS = {
    MAGIC_112: 0xFFFFFFFB, // Go 1.12
    MAGIC_116: 0xFFFFFFFA, // Go 1.16 
    MAGIC_118: 0xFFFFFFF0, // Go 1.18
    MAGIC_120: 0xFFFFFFF1, // Go 1.20+
    // Legacy magic numbers
    MAGIC_102: 0xFFFFFFF0, // Go 1.2-1.15 (legacy)
} as const;

interface PclnTabHeader {
    magic: number;
    pad1: number;
    pad2: number;
    minLC: number;
    ptrSize: number;
    nfunc: number;
    nfiles?: number;
    funcnameOffset?: number;
    cuOffset?: number;
    filetabOffset?: number;
    pctabOffset?: number;
    pclnOffset?: number;
    textStart?: number;
    funcnametab?: number;
    cutab?: number;
    filetab?: number;
    pctab?: number;
    funcdata?: number;
    functab?: number;
}

interface GoModuleData {
    textStart: NativePointer;
    textEnd: NativePointer;
    noptrdata: NativePointer;
    enoptrdata: NativePointer;
    data: NativePointer;
    edata: NativePointer;
    bss: NativePointer;
    ebss: NativePointer;
    noptrbss: NativePointer;
    enoptrbss: NativePointer;
    end: NativePointer;
    gcdata: NativePointer;
    gcbss: NativePointer;
    types: NativePointer;
    etypes: NativePointer;
    rodata: NativePointer;
    gofunc: NativePointer;
    textsectmap: NativePointer;
    typelinks: NativePointer;
    itablinks: NativePointer;
    ptab: NativePointer;
    pluginpath: NativePointer;
    pkghashes: NativePointer;
    modulename: NativePointer;
    modulehashes: NativePointer;
    hasmain: number;
    pclntab: NativePointer;
    functab: NativePointer;
    nfunctab: number;
    ftab: NativePointer;
    findfunctab: NativePointer;
    minpc: NativePointer;
    maxpc: NativePointer;
    next: NativePointer;
}

export class GoRuntimeParser {
    private module_name: string;
    private baseAddress: NativePointer;
    private moduleData: GoModuleData | null = null;
    private pclnHeader: PclnTabHeader | null = null;
    private functions: Map<string, GoFunction> = new Map();
    private goVersion: string = "unknown";
    private ptrSize: number = Process.pointerSize;
    private is64bit: boolean = Process.pointerSize === 8;
    private endianness: string = "little"; // Assume little endian
    private parsed: boolean = false;

    constructor(moduleName: string) {
        this.module_name = moduleName;
        try {
            const module = Process.getModuleByName(moduleName);
            this.baseAddress = module.base;
            this.detectArchitecture();
            this.initializeParser();
        } catch (err) {
            devlog(`[GoParser] Failed to initialize parser for ${moduleName}: ${err}`);
            this.baseAddress = ptr(0);
        }
    }
    
    private detectArchitecture(): void {
        this.ptrSize = Process.pointerSize;
        this.is64bit = this.ptrSize === 8;
        // Detect endianness if needed (most systems are little endian)
        this.endianness = "little";
        devlog(`[GoParser] Architecture: ${this.is64bit ? '64' : '32'}-bit, ptr_size=${this.ptrSize}, endianness=${this.endianness}`);
    }

    private initializeParser(): void {
        try {
            // Try to find and parse Go runtime structures
            this.findModuleData();
            if (this.moduleData) {
                this.parsePclnTab();
                this.parseFunctionTable();
            }
        } catch (err) {
            devlog(`[GoParser] Failed to initialize parser: ${err}`);
        }
    }

    // Find Go moduledata structure
    private findModuleData(): void {
        try {
            // Method 1: Look for runtime.firstmoduledata symbol
            let moduleDataAddr = this.findSymbol("runtime.firstmoduledata");
            if (!moduleDataAddr) {
                // Method 2: Pattern scan for moduledata structure
                moduleDataAddr = this.scanForModuleData();
            }

            if (moduleDataAddr) {
                this.moduleData = this.parseModuleData(moduleDataAddr);
                devlog(`[GoParser] Found moduledata at ${moduleDataAddr}`);
            }
        } catch (err) {
            devlog(`[GoParser] Failed to find moduledata: ${err}`);
        }
    }

    // Enhanced moduledata parsing with version-specific layouts
    private parseModuleData(addr: NativePointer): GoModuleData | null {
        try {
            const ptrSize = this.ptrSize;
            let offset = 0;
            
            // Parse core moduledata fields
            const textStart = addr.add(offset).readPointer(); offset += ptrSize;
            const textEnd = addr.add(offset).readPointer(); offset += ptrSize;
            const noptrdata = addr.add(offset).readPointer(); offset += ptrSize;
            const enoptrdata = addr.add(offset).readPointer(); offset += ptrSize;
            const data = addr.add(offset).readPointer(); offset += ptrSize;
            const edata = addr.add(offset).readPointer(); offset += ptrSize;
            const bss = addr.add(offset).readPointer(); offset += ptrSize;
            const ebss = addr.add(offset).readPointer(); offset += ptrSize;
            const noptrbss = addr.add(offset).readPointer(); offset += ptrSize;
            const enoptrbss = addr.add(offset).readPointer(); offset += ptrSize;
            const end = addr.add(offset).readPointer(); offset += ptrSize;
            const gcdata = addr.add(offset).readPointer(); offset += ptrSize;
            const gcbss = addr.add(offset).readPointer(); offset += ptrSize;
            const types = addr.add(offset).readPointer(); offset += ptrSize;
            const etypes = addr.add(offset).readPointer(); offset += ptrSize;
            
            // Skip some fields and find pclntab
            // The exact offset varies by Go version, so we'll search
            let pclntab: NativePointer = ptr(0);
            let functab: NativePointer = ptr(0);
            let nfunctab = 0;
            
            // Search for pclntab in reasonable range (optimized search)
            const searchStart = offset + ptrSize * 5; // Skip ahead
            const searchEnd = searchStart + ptrSize * 50;
            
            for (let searchOffset = searchStart; searchOffset < searchEnd; searchOffset += ptrSize) {
                try {
                    const potential_pclntab = addr.add(searchOffset).readPointer();
                    if (this.isValidPclnTab(potential_pclntab)) {
                        pclntab = potential_pclntab;
                        
                        // Try to find functab nearby
                        for (let j = 1; j <= 5; j++) {
                            try {
                                const potential_functab = addr.add(searchOffset + j * ptrSize).readPointer();
                                const potential_nfunctab = addr.add(searchOffset + (j + 1) * ptrSize).readU32();
                                
                                if (!potential_functab.isNull() && potential_nfunctab > 0 && potential_nfunctab < 100000) {
                                    functab = potential_functab;
                                    nfunctab = potential_nfunctab;
                                    break;
                                }
                            } catch {
                                continue;
                            }
                        }
                        break;
                    }
                } catch {
                    continue;
                }
            }
            
            if (pclntab.isNull()) {
                devlog(`[GoParser] Could not find valid pclntab in moduledata`);
                return null;
            }
            
            return {
                textStart, textEnd, noptrdata, enoptrdata, data, edata,
                bss, ebss, noptrbss, enoptrbss, end, gcdata, gcbss,
                types, etypes,
                rodata: ptr(0), gofunc: ptr(0), textsectmap: ptr(0),
                typelinks: ptr(0), itablinks: ptr(0), ptab: ptr(0),
                pluginpath: ptr(0), pkghashes: ptr(0), modulename: ptr(0),
                modulehashes: ptr(0), hasmain: 0,
                pclntab, functab, nfunctab,
                ftab: ptr(0), findfunctab: ptr(0),
                minpc: textStart, maxpc: textEnd, next: ptr(0)
            };
        } catch (err) {
            devlog(`[GoParser] Failed to parse moduledata: ${err}`);
            return null;
        }
    }

    // Enhanced pclntab validation with go_parser insights
    private isValidPclnTab(addr: NativePointer): boolean {
        try {
            if (addr.isNull()) return false;
            
            const magic = addr.readU32();
            const validMagics = Object.values(GO_MAGIC_NUMBERS) as number[];
            
            if (!validMagics.includes(magic)) {
                return false;
            }
            
            // Additional validation: check instruction size and pointer size
            const pad1 = addr.add(4).readU8();
            const pad2 = addr.add(5).readU8();
            const minLC = addr.add(6).readU8(); // Minimum instruction size
            const ptrSize = addr.add(7).readU8(); // Pointer size
            
            // Validate reasonable values
            if (ptrSize !== 4 && ptrSize !== 8) return false;
            if (minLC === 0 || minLC > 8) return false;
            
            return true;
        } catch {
            return false;
        }
    }
    
    // Get Go version string from magic number
    private getVersionFromMagic(magic: number): string {
        switch (magic) {
            case GO_MAGIC_NUMBERS.MAGIC_112: return "1.12";
            case GO_MAGIC_NUMBERS.MAGIC_116: return "1.16";
            case GO_MAGIC_NUMBERS.MAGIC_118: return "1.18";
            case GO_MAGIC_NUMBERS.MAGIC_120: return "1.20+";
            case GO_MAGIC_NUMBERS.MAGIC_102: return "1.2-1.15";
            default: return "unknown";
        }
    }

    // Enhanced pattern scan with multiple strategies from go_parser
    private scanForModuleData(): NativePointer | null {
        try {
            const module = Process.getModuleByName(this.module_name);
            
            // Strategy 1: Search in data sections first (most likely location)
            let result = this.scanDataSections(module);
            if (result) return result;
            
            // Strategy 2: Search in rodata sections
            result = this.scanRodataSections(module);
            if (result) return result;
            
            // Strategy 3: Exhaustive search in all readable sections
            result = this.scanAllReadableSections(module);
            if (result) return result;
            
            return null;
        } catch (err) {
            devlog(`[GoParser] Pattern scan failed: ${err}`);
            return null;
        }
    }
    
    private scanDataSections(module: any): NativePointer | null {
        try {
            const ranges = Process.enumerateRanges('rw-'); // Read-write data sections
            return this.scanRangesForModuleData(ranges, module);
        } catch {
            return null;
        }
    }
    
    private scanRodataSections(module: any): NativePointer | null {
        try {
            const ranges = Process.enumerateRanges('r--'); // Read-only data sections  
            return this.scanRangesForModuleData(ranges, module);
        } catch {
            return null;
        }
    }
    
    private scanAllReadableSections(module: any): NativePointer | null {
        try {
            const ranges = Process.enumerateRanges('r'); // All readable sections
            return this.scanRangesForModuleData(ranges, module);
        } catch {
            return null;
        }
    }
    
    private scanRangesForModuleData(ranges: any[], module: any): NativePointer | null {
        for (const range of ranges) {
            if (range.base.compare(module.base) >= 0 && 
                range.base.compare(module.base.add(module.size)) < 0) {
                
                const pattern = this.scanRangeForModuleData(range);
                if (pattern) return pattern;
            }
        }
        return null;
    }

    // Enhanced range scanning with improved heuristics
    private scanRangeForModuleData(range: any): NativePointer | null {
        try {
            const ptrSize = this.ptrSize;
            const stepSize = ptrSize; // Align to pointer boundaries
            const maxScanSize = Math.min(range.size, 10 * 1024 * 1024); // Limit scan size
            
            devlog(`[GoParser] Scanning range ${range.base} - ${range.base.add(maxScanSize)} for moduledata`);
            
            for (let offset = 0; offset < maxScanSize; offset += stepSize) {
                const addr = range.base.add(offset);
                
                try {
                    // Validate moduledata candidate with multiple checks
                    if (this.isValidModuleDataCandidate(addr)) {
                        devlog(`[GoParser] Found potential moduledata at ${addr}`);
                        return addr;
                    }
                } catch {
                    // Continue scanning on read errors
                    continue;
                }
            }
            
            return null;
        } catch (err) {
            devlog(`[GoParser] Range scan failed: ${err}`);
            return null;
        }
    }
    
    // Enhanced moduledata validation with multiple heuristics
    private isValidModuleDataCandidate(addr: NativePointer): boolean {
        try {
            const ptrSize = this.ptrSize;
            
            // Read potential text section pointers
            const textStart = this.safeReadPointer(addr);
            const textEnd = this.safeReadPointer(addr.add(ptrSize));
            
            if (!textStart || !textEnd || textStart.isNull() || textEnd.isNull()) {
                return false;
            }
            
            // Validate text section layout
            if (textEnd.compare(textStart) <= 0) {
                return false;
            }
            
            const textSize = textEnd.sub(textStart).toInt32();
            
            // Reasonable text section size (1KB to 200MB)
            if (textSize < 1024 || textSize > 200 * 1024 * 1024) {
                return false;
            }
            
            // Look for pclntab in various possible offsets
            const searchOffsets = [
                ptrSize * 15, ptrSize * 16, ptrSize * 17, ptrSize * 18, ptrSize * 19, ptrSize * 20,
                ptrSize * 21, ptrSize * 22, ptrSize * 23, ptrSize * 24, ptrSize * 25, ptrSize * 26,
                ptrSize * 27, ptrSize * 28, ptrSize * 29, ptrSize * 30, ptrSize * 31, ptrSize * 32
            ];
            
            for (const offset of searchOffsets) {
                const potentialPclntab = this.safeReadPointer(addr.add(offset));
                if (potentialPclntab && this.isValidPclnTab(potentialPclntab)) {
                    // Additional validation: check if this looks like a real moduledata
                    if (this.validateModuleDataStructure(addr, textStart, textEnd, potentialPclntab)) {
                        return true;
                    }
                }
            }
            
            return false;
        } catch {
            return false;
        }
    }
    
    // Additional structural validation for moduledata
    private validateModuleDataStructure(addr: NativePointer, textStart: NativePointer, textEnd: NativePointer, pclntab: NativePointer): boolean {
        try {
            const ptrSize = this.ptrSize;
            
            // Check that pclntab is within reasonable range of the binary
            const module = Process.getModuleByName(this.module_name);
            if (pclntab.compare(module.base) < 0 || pclntab.compare(module.base.add(module.size)) >= 0) {
                return false;
            }
            
            // Validate other moduledata fields for reasonable values
            const noptrdata = this.safeReadPointer(addr.add(ptrSize * 2));
            const data = this.safeReadPointer(addr.add(ptrSize * 4));
            
            if (noptrdata && data) {
                // noptrdata should be after textEnd
                if (noptrdata.compare(textEnd) < 0) {
                    return false;
                }
                
                // data should be after noptrdata (usually)
                if (data.compare(noptrdata) < 0) {
                    return false;
                }
            }
            
            return true;
        } catch {
            return false;
        }
    }

    // Enhanced PC Line Table parsing with go_parser insights
    private parsePclnTab(): void {
        if (!this.moduleData?.pclntab) return;
        
        try {
            const pclntab = this.moduleData.pclntab;
            const magic = pclntab.readU32();
            this.goVersion = this.getVersionFromMagic(magic);
            
            this.pclnHeader = {
                magic,
                pad1: pclntab.add(4).readU8(),
                pad2: pclntab.add(5).readU8(), 
                minLC: pclntab.add(6).readU8(),
                ptrSize: pclntab.add(7).readU8(),
                nfunc: 0
            };
            
            let offset = 8;
            
            // Version-specific parsing logic based on go_parser
            switch (magic) {
                case GO_MAGIC_NUMBERS.MAGIC_112:
                    // Go 1.12 format
                    this.pclnHeader.nfunc = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.nfiles = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.textStart = pclntab.add(offset).readU32(); offset += this.ptrSize;
                    this.pclnHeader.funcnametab = pclntab.add(offset).readU32(); offset += this.ptrSize;
                    this.pclnHeader.cutab = pclntab.add(offset).readU32(); offset += this.ptrSize;
                    this.pclnHeader.filetab = pclntab.add(offset).readU32(); offset += this.ptrSize;
                    this.pclnHeader.pctab = pclntab.add(offset).readU32(); offset += this.ptrSize;
                    this.pclnHeader.funcdata = pclntab.add(offset).readU32(); offset += this.ptrSize;
                    this.pclnHeader.functab = pclntab.add(offset).readU32();
                    break;
                    
                case GO_MAGIC_NUMBERS.MAGIC_116:
                case GO_MAGIC_NUMBERS.MAGIC_118:
                    // Go 1.16/1.18 format  
                    this.pclnHeader.nfunc = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.nfiles = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.funcnameOffset = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.cuOffset = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.filetabOffset = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.pctabOffset = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.pclnOffset = pclntab.add(offset).readU32();
                    break;
                    
                case GO_MAGIC_NUMBERS.MAGIC_120:
                    // Go 1.20+ format
                    this.pclnHeader.nfunc = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.nfiles = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.funcnameOffset = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.cuOffset = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.filetabOffset = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.pctabOffset = pclntab.add(offset).readU32(); offset += 4;
                    this.pclnHeader.pclnOffset = pclntab.add(offset).readU32();
                    break;
                    
                default:
                    // Legacy format (Go 1.2-1.15)
                    this.pclnHeader.nfunc = pclntab.add(offset).readU32();
                    break;
            }
            
            devlog(`[GoParser] Parsed pclntab header: version=${this.goVersion}, magic=0x${magic.toString(16)}, nfunc=${this.pclnHeader.nfunc}`);
        } catch (err) {
            devlog(`[GoParser] Failed to parse pclntab header: ${err}`);
        }
    }

    // Parse function table and extract function names/addresses
    private parseFunctionTable(): void {
        if (!this.moduleData?.functab || !this.pclnHeader) return;
        
        try {
            const functab = this.moduleData.functab;
            const pclntab = this.moduleData.pclntab;
            const nfunc = Math.min(this.pclnHeader.nfunc, 10000); // Limit for safety
            
            devlog(`[GoParser] Parsing ${nfunc} functions from functab`);
            
            for (let i = 0; i < nfunc; i++) {
                try {
                    const funcEntry = functab.add(i * this.ptrSize * 2);
                    const funcAddr = this.safeReadPointer(funcEntry);
                    
                    if (!funcAddr || funcAddr.isNull()) continue;
                    const funcInfoOffset = funcEntry.add(this.ptrSize).readU32();
                    
                    // Get function info
                    const funcInfo = pclntab.add(funcInfoOffset);
                    const nameOffset = funcInfo.readS32();
                    
                    // Enhanced function name reading with version-specific logic
                    let funcName = "";
                    
                    switch (this.pclnHeader.magic) {
                        case GO_MAGIC_NUMBERS.MAGIC_112:
                            // Go 1.12 format - name offset is relative to funcnametab
                            if (this.pclnHeader.funcnametab) {
                                const nameAddr = pclntab.add(this.pclnHeader.funcnametab + nameOffset);
                                funcName = this.safeReadCString(nameAddr) || "";
                            }
                            break;
                            
                        case GO_MAGIC_NUMBERS.MAGIC_116:
                        case GO_MAGIC_NUMBERS.MAGIC_118:
                        case GO_MAGIC_NUMBERS.MAGIC_120:
                            // Go 1.16+ format - name offset is relative to funcnameOffset
                            if (this.pclnHeader.funcnameOffset) {
                                const nameAddr = pclntab.add(this.pclnHeader.funcnameOffset + nameOffset);
                                funcName = this.safeReadCString(nameAddr) || "";
                            }
                            break;
                            
                        default:
                            // Legacy format - direct offset
                            const nameAddr = pclntab.add(nameOffset);
                            funcName = this.safeReadCString(nameAddr) || "";
                            break;
                    }
                    
                    if (funcName && funcName.length > 0) {
                        // Calculate function size with better error handling
                        let funcSize = 0;
                        let endAddress: NativePointer | undefined;
                        
                        if (i + 1 < nfunc) {
                            try {
                                const nextFuncEntry = functab.add((i + 1) * this.ptrSize * 2);
                                const nextFuncAddr = this.safeReadPointer(nextFuncEntry);
                                if (nextFuncAddr && !nextFuncAddr.isNull() && nextFuncAddr.compare(funcAddr) > 0) {
                                    funcSize = nextFuncAddr.sub(funcAddr).toInt32();
                                    endAddress = nextFuncAddr;
                                }
                            } catch {
                                // Ignore size calculation errors
                            }
                        }
                        
                        const goFunc: GoFunction = {
                            name: funcName,
                            address: funcAddr,
                            endAddress,
                            size: funcSize > 0 ? funcSize : undefined
                        };
                        
                        // Store under original name
                        this.functions.set(funcName, goFunc);
                        
                        // Store under mangled variants for better compatibility
                        const mangledName = this.createMangledName(funcName);
                        if (mangledName !== funcName) {
                            this.functions.set(mangledName, goFunc);
                        }
                        
                        // Store under partial name variants for fuzzy matching
                        const parts = funcName.split('.');
                        if (parts.length > 1) {
                            const shortName = parts[parts.length - 1];
                            if (shortName && !this.functions.has(shortName)) {
                                this.functions.set(shortName, goFunc);
                            }
                        }
                    }
                } catch (err) {
                    // Continue with next function on parse error
                    continue;
                }
            }
            
            devlog(`[GoParser] Successfully parsed ${this.functions.size} functions from ${nfunc} entries`);
            this.parsed = true;
        } catch (err) {
            devlog(`[GoParser] Failed to parse function table: ${err}`);
        }
    }
    
    // Enhanced initialization with retry logic
    public retryInitialization(): boolean {
        if (this.parsed) {
            return true;
        }
        
        try {
            devlog(`[GoParser] Retrying initialization for ${this.module_name}`);
            this.moduleData = null;
            this.pclnHeader = null;
            this.functions.clear();
            
            this.initializeParser();
            return this.parsed;
        } catch (err) {
            devlog(`[GoParser] Retry initialization failed: ${err}`);
            return false;
        }
    }
    
    // Check if parser was successfully initialized
    public isInitialized(): boolean {
        return this.parsed && this.functions.size > 0;
    }
    
    // Get parsing statistics
    public getParsingStats(): any {
        return {
            parsed: this.parsed,
            goVersion: this.goVersion,
            functionsFound: this.functions.size,
            moduleDataFound: this.moduleData !== null,
            pclnHeaderFound: this.pclnHeader !== null,
            architecture: `${this.is64bit ? '64' : '32'}-bit`,
            ptrSize: this.ptrSize
        };
    }

    // Enhanced function name cleaning based on go_parser
    private cleanFunctionName(name: string): string {
        if (!name) return "";
        
        // Remove null bytes and control characters
        name = name.replace(/[\x00-\x1F\x7F]/g, '');
        
        // Handle common Go name patterns
        name = name.trim();
        
        return name;
    }
    
    // Create mangled name variants
    private createMangledName(original: string): string {
        const cleaned = this.cleanFunctionName(original);
        return cleaned
            .replace(/\//g, '_')
            .replace(/\(\*([^)]+)\)/g, '_ptr_$1')
            .replace(/\./g, '_');
    }
    
    // Enhanced memory reading with error handling
    private safeReadPointer(addr: NativePointer): NativePointer | null {
        try {
            return addr.readPointer();
        } catch {
            return null;
        }
    }
    
    private safeReadU32(addr: NativePointer): number | null {
        try {
            return addr.readU32();
        } catch {
            return null;
        }
    }
    
    private safeReadCString(addr: NativePointer, maxLen: number = 256): string | null {
        try {
            const str = addr.readCString(maxLen);
            return str ? this.cleanFunctionName(str) : null;
        } catch {
            return null;
        }
    }

    // Find symbol by various methods
    private findSymbol(symbolName: string): NativePointer | null {
        try {
            // Try global export
            let addr = Module.getGlobalExportByName(symbolName);
            if (addr) return addr;
            
            // Try module export
            addr = Process.getModuleByName(this.module_name).getExportByName(symbolName);
            if (addr) return addr;
            
            // Try mangled variants
            const variants = [
                symbolName.replace(/\./g, '_'),
                symbolName.replace(/\//g, '_'),
                symbolName.replace(/\./g, '_').replace(/\//g, '_')
            ];
            
            for (const variant of variants) {
                try {
                    addr = Process.getModuleByName(this.module_name).getExportByName(variant);
                    if (addr) return addr;
                } catch {
                    continue;
                }
            }
            
            return null;
        } catch {
            return null;
        }
    }

    // Public API: Find function by name
    public findFunction(functionName: string): GoFunction | null {
        // First check parsed functions
        let func = this.functions.get(functionName);
        if (func) return func;
        
        // Try mangled variants
        const mangledName = this.createMangledName(functionName);
        func = this.functions.get(mangledName);
        if (func) return func;
        
        // Try partial matches
        for (const [name, goFunc] of this.functions) {
            if (name.includes(functionName) || functionName.includes(name)) {
                return goFunc;
            }
        }
        
        return null;
    }

    // Public API: Get all functions matching pattern
    public findFunctionsMatching(pattern: string): GoFunction[] {
        const results: GoFunction[] = [];
        const regex = new RegExp(pattern, 'i');
        
        for (const [name, func] of this.functions) {
            if (regex.test(name)) {
                results.push(func);
            }
        }
        
        return results;
    }

    // Public API: Get all TLS-related functions
    public getTLSFunctions(): GoFunction[] {
        const tlsPatterns = [
            'crypto/tls',
            'tls\\..*Conn',
            'tls\\..*Config',
            'writeKeyLog',
            'Read',
            'Write',
            'updateTrafficSecret',
            'nextTrafficSecret',
            'hkdf'
        ];
        
        const results: GoFunction[] = [];
        for (const pattern of tlsPatterns) {
            results.push(...this.findFunctionsMatching(pattern));
        }
        
        // Remove duplicates
        const unique = new Map<string, GoFunction>();
        for (const func of results) {
            unique.set(func.address.toString(), func);
        }
        
        return Array.from(unique.values());
    }

    // Public API: Debug information
    public getDebugInfo(): any {
        return {
            module_name: this.module_name,
            baseAddress: this.baseAddress.toString(),
            moduleData: this.moduleData ? {
                textStart: this.moduleData.textStart.toString(),
                textEnd: this.moduleData.textEnd.toString(),
                pclntab: this.moduleData.pclntab.toString(),
                functab: this.moduleData.functab.toString(),
                nfunctab: this.moduleData.nfunctab
            } : null,
            pclnHeader: this.pclnHeader,
            functionsFound: this.functions.size,
            sampleFunctions: Array.from(this.functions.keys()).slice(0, 10)
        };
    }

    // Public API: List all functions (for debugging)
    public listAllFunctions(): void {
        devlog(`[GoParser] Found ${this.functions.size} functions in ${this.module_name}:`);
        
        const tlsFunctions = Array.from(this.functions.entries())
            .filter(([name]) => name.toLowerCase().includes('tls') || 
                                name.toLowerCase().includes('crypto') ||
                                name.toLowerCase().includes('conn') ||
                                name.toLowerCase().includes('config'))
            .slice(0, 20); // Limit output
        
        for (const [name, func] of tlsFunctions) {
            devlog(`[GoParser]   ${name} @ ${func.address}${func.size ? ` (size: ${func.size})` : ''}`);
        }
        
        if (tlsFunctions.length === 0) {
            devlog(`[GoParser] No TLS-related functions found. Sample functions:`);
            const sampleFunctions = Array.from(this.functions.entries()).slice(0, 10);
            for (const [name, func] of sampleFunctions) {
                devlog(`[GoParser]   ${name} @ ${func.address}`);
            }
        }
    }
}