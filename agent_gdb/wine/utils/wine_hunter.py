import argparse
import contextlib
import json
import tempfile
from pathlib import Path

import pyghidra
from jpype import JArray, JByte


def _load_binary(project, path):
    name = Path(path).name
    prog_path = f"/{name}"
    if project.getProjectData().getFile(prog_path) is not None:
        print(f"{name}: reusing existing project entry")
        return prog_path
    loader = (
        pyghidra.program_loader()
        .project(project)
        .source(str(path))
        .projectFolderPath("/")
    )
    with loader.load() as load_results:
        load_results.save(pyghidra.task_monitor())
    return prog_path


def _analyze_if_needed(program):
    from ghidra.program.util import GhidraProgramUtilities

    if GhidraProgramUtilities.shouldAskToAnalyze(program):
        pyghidra.analyze(program)
        program.save("Analyzed", pyghidra.task_monitor())


def _read_bytes(program, addr, size):
    byte_array = JArray(JByte)(size)
    program.getMemory().getBytes(addr, byte_array)
    return byte_array


def analyze_ntdll_dll(project, path):
    result = {
        "name": "LdrLoadDll@ntdll.dll windows",
        "handler": "LdrLoadDLLWindowsBP",
        "offset": 0,
    }
    prog_path = _load_binary(project, path)
    with pyghidra.program_context(project, prog_path) as program:
        _analyze_if_needed(program)

        fm = program.getFunctionManager()
        main = None
        for func in fm.getFunctions(True):
            if func.getName() == "LdrLoadDll":
                main = func
                addr = main.getEntryPoint()

        if not main:
            print("LdrLoadDll not found in wine, exiting")
            return result

        byte_array = _read_bytes(program, addr, 32)
        signature = bytes([int(x % 256) for x in byte_array]).hex()

    return {signature: result}


def analyze_dll_main(project, path):
    result = {
        "name": "DllMain@ntdll.dll windows",
        "handler": "FindHookablesBP",
        "offset": 0,
    }
    prog_path = _load_binary(project, path)
    with pyghidra.program_context(project, prog_path) as program:
        _analyze_if_needed(program)

        fm = program.getFunctionManager()
        main = None
        for func in fm.getFunctions(True):
            if func.getName() == "DllMain":
                main = func
                addr = main.getEntryPoint()

        if not main:
            print("DllMain not found in wine, exiting")
            return result

        byte_array = _read_bytes(program, addr, 32)
        signature = bytes([int(x % 256) for x in byte_array]).hex()

    return {signature: result}


def analyze_ntdll_so(project, path):
    result = {
        "name": "__wine_main@ntdll.so unix",
        "handler": "FindHookablesBP",
        "offset": 0,
    }
    prog_path = _load_binary(project, path)
    with pyghidra.program_context(project, prog_path) as program:
        _analyze_if_needed(program)

        fm = program.getFunctionManager()
        main = None
        for func in fm.getFunctions(True):
            if func.getName() == "__wine_main":
                main = func
                addr = main.getEntryPoint()

        if not main:
            print("__wine_main not found in wine, exiting")
            return result

        byte_array = _read_bytes(program, addr, 32)
        signature = bytes([int(x % 256) for x in byte_array]).hex()

        listing = program.getListing()
        for instr in listing.getInstructions(main.getBody(), True):
            if not instr.getFlowType().isCall():
                continue
            for target in instr.getFlows():
                callee = fm.getFunctionAt(target)
                if callee and callee.getName() == "server_init_process_done":
                    offset = int(instr.getAddress().getOffset()) - int(
                        main.getEntryPoint().getOffset()
                    )
                    result["offset"] = offset

    return {signature: result}


def analyze_wine_preloader(project, path):
    result = {
        "name": "_start@wine-preloader unix",
        "handler": "FindHookablesBP",
        "offset": 0,
    }
    prog_path = _load_binary(project, path)
    with pyghidra.program_context(project, prog_path) as program:
        _analyze_if_needed(program)

        fm = program.getFunctionManager()
        main = None
        for func in fm.getFunctions(True):
            if func.getName() == "_start":
                main = func
                addr = main.getEntryPoint()

        if not main:
            print("_start not found in wine-preloader, exiting")
            return result

        byte_array = _read_bytes(program, addr, 32)
        signature = bytes([int(x % 256) for x in byte_array]).hex()

        listing = program.getListing()
        for instr in listing.getInstructions(main.getBody(), True):
            if not instr.getFlowType().isCall():
                continue
            for target in instr.getFlows():
                callee = fm.getFunctionAt(target)
                if callee and callee.getName() == "wld_start":
                    next_instr = listing.getInstructionAfter(instr.getAddress())
                    if next_instr:
                        offset = int(next_instr.getAddress().getOffset()) - int(
                            main.getEntryPoint().getOffset()
                        )
                        result["offset"] = offset

    return {signature: result}


def analyze_wine(project, path):
    result = {"name": "main@wine unix", "handler": "FindHookablesBP", "offset": 0}
    prog_path = _load_binary(project, path)
    with pyghidra.program_context(project, prog_path) as program:
        _analyze_if_needed(program)

        fm = program.getFunctionManager()
        main = None
        for func in fm.getFunctions(True):
            if func.getName() == "main":
                main = func
                addr = main.getEntryPoint()

        if not main:
            print("main not found in wine, exiting")
            return result

        byte_array = _read_bytes(program, addr, 32)
        signature = bytes([int(x % 256) for x in byte_array]).hex()

        listing = program.getListing()
        for instr in listing.getInstructions(main.getBody(), True):
            if not instr.getFlowType().isCall():
                continue
            for target in instr.getFlows():
                callee = fm.getFunctionAt(target)
                if callee and callee.getName() == "dlsym":
                    next_instr = listing.getInstructionAfter(instr.getAddress())
                    if next_instr:
                        offset = int(next_instr.getAddress().getOffset()) - int(
                            main.getEntryPoint().getOffset()
                        )
                        result["offset"] = offset

    return {signature: result}


def analyze_gnutls(project, path):
    """Extract the GnuTLS keylog hook signature from libgnutls.so.

    Two shapes exist across builds:

    * builds that keep ``_gnutls_call_keylog_func`` as a standalone function
      -> hook it directly (handler ``GnuTLSCallKeylogUnixBP``);
    * builds that *inline* ``_gnutls_call_keylog_func`` into the key schedule
      (e.g. Ubuntu gnutls 3.8.x) -> there is no standalone function, so hook the
      registered NSS keylog *callback* instead (handler
      ``GnuTLSNssKeylogFuncUnixBP``). gnutls invokes that callback for every
      secret of every handshake, so capture stays passive.

    The keylog symbols are usually stripped, so we try symbol names first and
    then fall back to locating the callback via references to the exported
    ``gnutls_session_set_keylog_function`` (its 2nd argument is the callback).

    Best-effort/static: validate the emitted signature on the live library (the
    dynamic gdb method documented in docs/platforms/wine.md) before relying on it.
    """
    prog_path = _load_binary(project, path)
    with pyghidra.program_context(project, prog_path) as program:
        _analyze_if_needed(program)
        fm = program.getFunctionManager()
        listing = program.getListing()

        # 1) Direct symbol hit (debug/unstripped builds).
        direct = {
            "_gnutls_call_keylog_func": "GnuTLSCallKeylogUnixBP",
            "_gnutls_nss_keylog_func": "GnuTLSNssKeylogFuncUnixBP",
            "nss_keylog_func": "GnuTLSNssKeylogFuncUnixBP",
        }
        for func in fm.getFunctions(True):
            handler = direct.get(func.getName())
            if handler:
                sig = bytes(
                    int(x % 256) for x in _read_bytes(program, func.getEntryPoint(), 32)
                ).hex()
                return {sig: {"name": f"{func.getName()} unix", "handler": handler, "offset": 0}}

        # 2) Fallback: find the callback passed to gnutls_session_set_keylog_function.
        setter = next(
            (f for f in fm.getFunctions(True)
             if f.getName() == "gnutls_session_set_keylog_function"),
            None,
        )
        if setter is None:
            print("gnutls: neither keylog symbols nor the setter were found, skipping")
            return {}

        ref_mgr = program.getReferenceManager()
        for ref in ref_mgr.getReferencesTo(setter.getEntryPoint()):
            call_instr = listing.getInstructionAt(ref.getFromAddress())
            if call_instr is None:
                continue
            # The callback address is loaded (lea/mov) shortly before the call.
            cur = call_instr
            for _ in range(16):
                cur = listing.getInstructionBefore(cur.getAddress())
                if cur is None:
                    break
                for r in cur.getReferencesFrom():
                    callee = fm.getFunctionAt(r.getToAddress())
                    if callee is not None and callee != setter:
                        sig = bytes(
                            int(x % 256)
                            for x in _read_bytes(program, callee.getEntryPoint(), 32)
                        ).hex()
                        return {
                            sig: {
                                "name": "gnutls nss keylog callback unix",
                                "handler": "GnuTLSNssKeylogFuncUnixBP",
                                "offset": 0,
                            }
                        }

        print("gnutls: could not resolve the keylog callback, skipping")
        return {}


def main():
    parser = argparse.ArgumentParser(
        prog="Wine Hunter",
        description="""Extract signatures and offsets for use with friTap's gdb backend and wine
                    Please provide the following binaries in the input directory
                    wine,            commonly found in /usr/lib64/wine-wow64/wine/x86_64-unix/wine
                    ntdll.so,        commonly found in /usr/lib64/wine-wow64/wine/x86_64-unix/ntdll.so
                    wine-preloader,  commonly found in /usr/lib64/wine-wow64/wine/x86_64-unix/wine-preloader
                    ntdll.dll,       commonly found in /home/<user>/.wine/drive_c/windows/syswow64/ntdll.dll
                    libgnutls.so.30, the host GnuTLS used by Wine's Schannel, commonly /lib/x86_64-linux-gnu/libgnutls.so.30 (optional)
                    """,
    )
    parser.add_argument("-i", "--input-dir", default="inputs")
    parser.add_argument(
        "-p",
        "--project-dir",
        default=None,
        help="Directory to store the Ghidra project. Re-using the same directory skips "
        "re-importing on successive runs. Defaults to a temporary directory.",
    )
    parser.add_argument(
        "-j",
        "--json",
        metavar="FILE",
        default=None,
        help="Write results as JSON to FILE. Use '-' to print to stdout.",
    )
    args = parser.parse_args()

    if not Path(args.input_dir).is_dir():
        parser.print_help()
        exit()

    pyghidra.start()

    results = {}

    if args.project_dir:
        Path(args.project_dir).mkdir(parents=True, exist_ok=True)
        project_dir_ctx = contextlib.nullcontext(args.project_dir)
    else:
        project_dir_ctx = tempfile.TemporaryDirectory()

    with project_dir_ctx as project_dir:
        with pyghidra.open_project(
            Path(project_dir).resolve(), "wine_hunter", create=True
        ) as project:
            if not (Path(args.input_dir) / "ntdll.dll").is_file():
                print("ntdll.dll missing")
            else:
                print("Analyzing ntdll.dll")
                results.update(
                    analyze_ntdll_dll(project, Path(args.input_dir) / "ntdll.dll")
                )
                results.update(
                    analyze_dll_main(project, Path(args.input_dir) / "ntdll.dll")
                )

            if not (Path(args.input_dir) / "ntdll.so").is_file():
                print("ntdll.so missing")
            else:
                print("Analyzing ntdll.so")
                results.update(
                    analyze_ntdll_so(project, Path(args.input_dir) / "ntdll.so")
                )

            if not (Path(args.input_dir) / "wine-preloader").is_file():
                print("wine-preloader missing")
            else:
                print("Analyzing wine-preloader")
                results.update(
                    analyze_wine_preloader(
                        project, Path(args.input_dir) / "wine-preloader"
                    )
                )

            if not (Path(args.input_dir) / "wine").is_file():
                print("wine missing")
            else:
                print("Analyzing wine")
                results.update(analyze_wine(project, Path(args.input_dir) / "wine"))

            # GnuTLS keylog signature (native libgnutls, as used by Wine's
            # Schannel). Accept libgnutls.so, libgnutls.so.30, etc.
            gnutls_inputs = sorted(Path(args.input_dir).glob("libgnutls.so*"))
            if not gnutls_inputs:
                print("libgnutls.so* missing")
            else:
                print(f"Analyzing {gnutls_inputs[0].name}")
                results.update(analyze_gnutls(project, gnutls_inputs[0]))

    json_output = json.dumps(results, indent=4)

    print("Signatures and Offsets found:")
    print(json_output)

    print("Without indent:")
    print(json.dumps(results))

    if args.json and args.json != "-":
        Path(args.json).write_text(json_output)
        print(f"Results written to {args.json}")


if __name__ == "__main__":
    main()
