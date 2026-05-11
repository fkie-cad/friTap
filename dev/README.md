# friTap Development Tools

This directory contains development scripts, build tools, and CI support files for friTap.

## Prerequisites

- **Python 3.10+**
- **Node.js 16+**
- **Git**

## Build from Source

```bash
# 1. Clone the repository
git clone https://github.com/fkie-cad/friTap.git
cd friTap

# 2. Create and activate a virtual environment
python -m venv env
source env/bin/activate    # Linux/macOS
# env\Scripts\activate     # Windows

# 3. Install Python dependencies
pip install -e .[dev]

# 4. Install frida-tools (provides frida-compile) and Frida module dependencies
pip install frida-tools
frida-pm install frida-objc-bridge frida-java-bridge

# 5. Compile the TypeScript agent
frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js
# or: ./dev/compile_agent.sh    (Linux/macOS)
# or: dev\compile_agent.bat     (Windows)

# 6. Run the test suite
python dev/run_tests.py all

# 7. Regenerate TypeScript schema types (after modifying Pydantic models)
python dev/generate_agent_types.py

# 8. Docker build (optional)
docker build -f dev/Dockerfile .
```

## Scripts

| Script | Purpose |
|---|---|
| `compile_agent.sh` / `compile_agent.bat` | Compile the TypeScript agent to JavaScript |
| `generate_agent_types.py` | Generate `agent/schemas/messages.ts` from Pydantic models |
| `run_tests.py` | Unified test runner (unit, integration, agent, coverage) |
| `setup_dev.py` | Automated dev environment setup |
| `entrypoint.sh` | Docker container entrypoint |
| `Dockerfile` | Docker image for agent compilation |
