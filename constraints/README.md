# Legacy install constraints

friTap 1.x releases on PyPI were published with **floor-only** dependency
pins (e.g. `frida>=16.0.0`, no upper cap). Today, `pip install fritap==1.3.4.0`
therefore resolves to the **latest** frida (17.x) and **latest** frida-tools
(14.x) — not the era-matched frida 16.x / frida-tools 11.x the 1.3.4.0
agent was built against. The agent then silently misbehaves at runtime.

PyPI metadata is immutable, so legacy releases cannot be retroactively
re-pinned. The files in this directory are **pip constraints files**
(`-c` flag) that cap the transitive `frida` / `frida-tools` versions to the
era matching each friTap 1.x range, without modifying any released artifact.

## Which file do I want?

Match your `frida-server` major version to the row below.

| Your frida-server | friTap range to install | Constraints file              |
|-------------------|-------------------------|-------------------------------|
| 15.x              | 1.3.0.0 – 1.3.3.3       | `constraints/frida15.txt`     |
| 16.x              | 1.3.4.0 – 1.4.3.0       | `constraints/frida16.txt`     |
| 17.x (legacy)     | 1.4.4.0 – 1.6.3.1       | `constraints/frida17-legacy.txt` |
| 17.x (current)    | 2.0.0+                  | (none — current `requirements.txt` is strict) |

The era boundaries are also encoded machine-readably in `compat.yml` under
the `era_boundaries` key.

## How to install

Three equivalent recipes; pick whichever fits your workflow.

**A. Raw pip, no local clone** — uses the constraints file directly from
GitHub `main`:

```bash
pip install fritap==1.4.3.0 \
  -c https://raw.githubusercontent.com/fkie-cad/friTap/main/constraints/frida16.txt
```

**B. Local clone + helper script** — convenience wrapper, picks the
top-of-era friTap version automatically:

```bash
git clone https://github.com/fkie-cad/friTap && cd friTap
python dev/install_legacy.py --frida-major 16
```

**C. Local clone + raw pip** — same as A, but reads the constraints file
from the local checkout:

```bash
git clone https://github.com/fkie-cad/friTap && cd friTap
pip install fritap==1.4.3.0 -c constraints/frida16.txt
```

All three install friTap from PyPI (the wheel ships pre-built
`friTap/fritap_agent.js`) plus the era-matched `frida` / `frida-tools`.

## What these files do NOT solve

**Python interpreter compatibility.** frida wheels for 15.x and 16.x were
built when older Python versions were current. If your interpreter is
newer than what frida shipped wheels for (e.g. Python 3.14 against
frida 15.x), pip will report:

```
ERROR: Could not find a version that satisfies the requirement frida
```

Workaround: install an older interpreter (`pyenv install 3.11.x`) into a
dedicated venv and use that for the legacy install.

**`pip install -e .` from a legacy git tag.** Legacy tags
(`v1.4.1.9`, etc.) do not commit `friTap/fritap_agent.js`, so an editable
install from a checkout fails at runtime. The recipes above install from
PyPI for this reason — the PyPI wheel/sdist contains the pre-built agent.

## Verifying the resolved versions

After running any recipe, confirm pip picked the era-matched versions:

```bash
pip show frida        | grep -E '^(Name|Version)'
pip show frida-tools  | grep -E '^(Name|Version)'
pip show friTap       | grep -E '^(Name|Version)'
```

For the frida-16 recipe, expect frida 16.x.x (latest 16-line patch),
frida-tools 12.x or 13.x (the lines that target frida 16), friTap 1.4.3.0.

### Why frida-tools 12.x/13.x for frida 16 (not 11.x)?

frida-tools maintains its own version line independent of frida's major:

| frida-tools major | frida it targets       |
|-------------------|------------------------|
| 10.x              | frida 14.x (and 15.x)  |
| 11.x              | frida 15.2+            |
| 12.x              | frida 16.0.9+          |
| 13.x              | frida 16.2.2+          |
| 14.x              | frida 17.x             |

Old friTap wheels carried `frida-tools>=11.0.0` (frida-16 era) as a
release-time floor, not an era match. At install time today, pip will
pick whatever it can — left unconstrained, that means 14.x, which rejects
frida 16. The constraints files map each frida major to the actual
compatible frida-tools range.
