"""Standalone command for tlshunter."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tlshunter import Config, observe, summarize
else:
    from . import Config, observe, summarize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--user", required=True, type=int)
    parser.add_argument("--package", required=True, action="append")
    parser.add_argument("--seconds", type=float, default=10)
    parser.add_argument("--interval", type=float, default=1)
    parser.add_argument("--su", action="store_true")
    args = parser.parse_args()
    samples = []
    try:
        config = Config(args.device, args.user, tuple(args.package),
                        args.seconds, args.interval, args.su)
        for record in observe(config):
            if record["type"] == "phase" and record["phase"] == "interaction":
                print("Trigger the interaction now.", file=sys.stderr, flush=True)
            print(json.dumps(record), flush=True)
            samples.append(record)
        print(json.dumps(summarize(samples)), flush=True)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        print(f"tlshunter: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
