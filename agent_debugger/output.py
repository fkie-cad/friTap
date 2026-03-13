"""Keylog file writer for extracted keys."""

import os


class KeylogWriter:
    """Appends key log lines to a file.

    The output file path is determined by an environment variable,
    falling back to a default path if the variable is not set.
    """

    def __init__(self, env_var: str, default_file: str):
        self.filepath = os.environ.get(env_var, default_file)

    def write_line(self, line: str) -> None:
        with open(self.filepath, "a") as f:
            f.write(line + "\n")

    def write_lines(self, lines: list[str]) -> None:
        if lines:
            with open(self.filepath, "a") as f:
                for line in lines:
                    f.write(line + "\n")
