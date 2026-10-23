# Utils

## `wine_hunter.py`

Utilizes [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/tree/master/Ghidra/Features/PyGhidra)
to statically analyze Wine binaries, to find function signatures for instrumenting the call chain from wine to the running windows program:

The generated patterns can be used with `wine_key_extract.py`, by using the `--patterns` option.

### Input binaries

Place the following binaries in the input directory (default: `inputs/`):

| File             | Typical location                                              |
|------------------|-----------------------------------------------------------------|
| `wine`           | `/usr/lib64/wine-wow64/wine/x86_64-unix/wine`                  |
| `ntdll.so`       | `/usr/lib64/wine-wow64/wine/x86_64-unix/ntdll.so`               |
| `wine-preloader` | `/usr/lib64/wine-wow64/wine/x86_64-unix/wine-preloader`         |
| `ntdll.dll`      | `~/.wine/drive_c/windows/syswow64/ntdll.dll`                    |

Missing binaries are skipped (with a warning) rather than aborting the run.

### Usage

```sh
python wine_hunter.py -i inputs/ -j patterns.json
```

Options:

- `-i, --input-dir` — directory containing the input binaries (default: `inputs`)
- `-p, --project-dir` — directory to store the Ghidra project; reusing it
  skips re-importing binaries on later runs (default: a temporary directory)
- `-j, --json FILE` — write the resulting signatures/offsets as JSON to
  `FILE` (use `-` to print to stdout)
