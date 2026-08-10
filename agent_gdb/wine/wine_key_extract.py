#!/usr/bin/env python3

import subprocess
import argparse
import pathlib
import json
import sys
import os


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wine_key_extract.py",
        description="Export TLS-Keys from running wine programs",
        usage="\n"
        r"%(prog)s --spawn prog.exe -k output.log -- <program arguments>"
        "\n"
        r"%(prog)s --attach 6548 -k output.log"
        "\n"
        r"%(prog)s --spawn prog.exe -k output.log --patterns patterns.json -- <program arguments>",
    )
    parser.add_argument(
        "-a", "--attach", metavar="PID", help="PID of program to attach to"
    )
    parser.add_argument("-s", "--spawn", metavar="EXECUTABLE", help="Program to spawn")
    parser.add_argument(
        "-k",
        "--keylog",
        metavar="LOCATION",
        help="write extracted keys to this file location",
    )
    parser.add_argument(
        "-p",
        "--patterns",
        metavar="FILE",
        help="functions patterns to hook",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="enable verbose logging",
    )
    parser.add_argument(
        "-do",
        "--debug-output",
        dest="debug_output",
        action="store_true",
        help="enable debug output",
    )
    parser.add_argument(
        "-g",
        "--gdb",
        action="store_true",
        help="print gdb output for debugging"
    )
    parser.add_argument(
        "program_args",
        nargs=argparse.REMAINDER,
        help=r"Arguments to pass to TARGET when spawning it (requires --spawn), "
        r"e.g. %(prog)s --spawn ./foo -- --bar baz",
    )

    return parser


def main() -> int:
    script_path = (
        pathlib.Path(__file__).resolve().parent / "gdb_script" / "gdb_wine_extract.py"
    )

    args = build_parser().parse_args()

    log_fd = os.dup(sys.stdout.fileno())
    stdout_fd = os.dup(sys.stdout.fileno())
    stderr_fd = os.dup(sys.stderr.fileno())


    environment = os.environ.copy()
    arguments = vars(args)
    arguments["log-fd"] = log_fd
    arguments["stdout-fd"] = stdout_fd
    arguments["stderr-fd"] = stderr_fd
    environment["FRITAP_ARGS"] = json.dumps(arguments)

    try:
        if not args.gdb:
            subprocess.run(["gdb", "-ex", " set debuginfod enabled off ", "-x", str(script_path)], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(log_fd, stdout_fd, stderr_fd))
        else:
            subprocess.run(["gdb", "-ex", " set debuginfod enabled off ", "-x", str(script_path)], env=environment, pass_fds=(log_fd, stdout_fd, stderr_fd))
    finally:
        os.close(log_fd)

if __name__ == "__main__":
    sys.exit(main())
