#!/usr/bin/env python3
"""
friTap Development Environment Setup Script

Automated setup script for friTap development environment.
Handles dependency installation, environment configuration, and validation.
"""

import json
import shutil
import sys
import subprocess
import platform
import traceback
from pathlib import Path


class FriTapDevSetup:
    """Automated development environment setup for friTap."""

    def __init__(self):
        self.root_dir = Path(__file__).parent.parent
        self.platform = platform.system().lower()
        self.python_executable = sys.executable

    def run_command(self, cmd, description="", check=True, capture_output=False):
        """Run a command with error handling. cmd must be a list."""
        print(f"  [INFO] {description}")
        try:
            result = subprocess.run(
                cmd,
                check=check,
                capture_output=capture_output,
                text=True,
                cwd=self.root_dir,
            )

            if capture_output:
                return result
            else:
                print("  [OK] Success")
                return True

        except subprocess.CalledProcessError as e:
            print(f"  [FAIL] Failed: {e}")
            if capture_output:
                print(f"   stdout: {e.stdout}")
                print(f"   stderr: {e.stderr}")
            return False
        except FileNotFoundError as e:
            print(f"  [FAIL] Command not found: {e}")
            return False

    def check_command_exists(self, command):
        """Check if a command exists in PATH."""
        return shutil.which(command) is not None

    def check_python_version(self):
        """Check Python version compatibility."""
        print("[INFO] Checking Python version...")

        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 10):
            print(f"  [FAIL] Python {version.major}.{version.minor} is not supported")
            print("   friTap requires Python 3.10 or later")
            return False

        print(f"  [OK] Python {version.major}.{version.minor}.{version.micro} is supported")
        return True

    def check_git(self):
        """Check Git availability."""
        print("[INFO] Checking Git...")

        result = self.run_command(
            ["git", "--version"],
            "Checking Git version",
            check=False,
            capture_output=True,
        )

        if not result or result.returncode != 0:
            print("  [WARN] Git not found")
            print("   Git is recommended for development")
            return False

        version = result.stdout.strip()
        print(f"  [OK] {version}")
        return True

    def install_python_dependencies(self):
        """Install Python development dependencies."""
        print("[INFO] Installing Python dependencies...")

        # Install development dependencies
        if not self.run_command(
            [self.python_executable, "-m", "pip", "install", "-r", "requirements-dev.txt"],
            "Installing development dependencies",
        ):
            return False

        # Install friTap in development mode
        if not self.run_command(
            [self.python_executable, "-m", "pip", "install", "-e", "."],
            "Installing friTap in development mode",
        ):
            return False

        return True

    def install_frida_tools(self):
        """Install frida-tools (provides frida-compile) and Frida bridge modules."""
        print("[INFO] Installing frida-tools and Frida modules...")

        # Install frida-tools (provides frida-compile CLI)
        if not self.run_command(
            [self.python_executable, "-m", "pip", "install", "frida-tools"],
            "Installing frida-tools (provides frida-compile)",
        ):
            return False

        # Install Frida bridge modules via frida-pm
        if not self.run_command(
            ["frida-pm", "install", "frida-objc-bridge", "frida-java-bridge"],
            "Installing Frida ObjC and Java bridge modules",
        ):
            print("  [WARN] frida-pm install failed, bridges may not be available")
            # Don't fail the whole setup for this

        return True

    def setup_frida_compile(self):
        """Validate that frida-compile is available after install."""
        print("[INFO] Validating frida-compile availability...")

        if not self.check_command_exists("frida-compile"):
            print("  [FAIL] frida-compile not found after installing frida-tools")
            print("   You may need to add your Python scripts directory to PATH")
            return False

        # Check frida-compile version
        result = self.run_command(
            ["frida-compile", "--version"],
            "Checking frida-compile version",
            check=False,
            capture_output=True,
        )

        if result and result.returncode == 0:
            print(f"  [OK] frida-compile {result.stdout.strip()} available")
        else:
            print("  [WARN] frida-compile installed but version check failed")

        print("  [OK] frida-compile setup complete")
        return True

    def test_agent_compilation(self):
        """Test TypeScript agent compilation using frida-compile."""
        print("[INFO] Testing agent compilation...")

        if not self.run_command(
            ["frida-compile", "agent/fritap_agent.ts", "-o", "friTap/fritap_agent.js"],
            "Compiling TypeScript agent with frida-compile",
        ):
            print("  [FAIL] Agent compilation failed")
            print("   Check that all TypeScript files are valid")
            return False

        # Check if compiled file exists
        fritap_agent_js = self.root_dir / "friTap" / "fritap_agent.js"
        if fritap_agent_js.exists():
            print(f"  [OK] Agent compilation successful: {fritap_agent_js}")
            return True
        else:
            print("  [FAIL] Compiled agent file not found")
            return False

    def setup_boringsecrethunter(self):
        """Set up BoringSecretHunter Docker environment."""
        print("[INFO] Setting up BoringSecretHunter environment...")

        if not self.check_command_exists("docker"):
            print("  [FAIL] Docker is not installed")
            print("   Please install Docker from: https://docker.com/")
            print("   BoringSecretHunter requires Docker for the best experience")
            return False

        print("  [OK] Docker detected")

        # Create directories for BoringSecretHunter
        binary_dir = self.root_dir / "binary"
        results_dir = self.root_dir / "results"
        binary_dir.mkdir(exist_ok=True)
        results_dir.mkdir(exist_ok=True)
        print("  [OK] Created binary/ and results/ directories for BoringSecretHunter")

        # Test Docker access
        result = self.run_command(
            ["docker", "info"],
            "Testing Docker access",
            check=False,
            capture_output=True,
        )

        if not result or result.returncode != 0:
            print("  [WARN] Docker access test failed - you may need to start Docker daemon")
            print("   BoringSecretHunter will be available once Docker is running")
            return True

        print("  [OK] BoringSecretHunter environment ready")
        return True

    def setup_pre_commit(self):
        """Setup pre-commit hooks."""
        print("[INFO] Setting up pre-commit hooks...")

        # Check if pre-commit is available
        result = self.run_command(
            [self.python_executable, "-m", "pre_commit", "--version"],
            "Checking pre-commit availability",
            check=False,
            capture_output=True,
        )

        if not result or result.returncode != 0:
            print("  [WARN] pre-commit not available, skipping hooks setup")
            return True

        # Install pre-commit hooks
        if not self.run_command(
            [self.python_executable, "-m", "pre_commit", "install"],
            "Installing pre-commit hooks",
        ):
            print("  [WARN] Failed to install pre-commit hooks")
            return False

        return True

    def validate_setup(self):
        """Validate the development setup."""
        print("[INFO] Validating development setup...")

        # Test friTap import
        result = self.run_command(
            [self.python_executable, "-c", "import friTap; print('friTap import: OK')"],
            "Testing friTap import",
            capture_output=True,
        )

        if not result or result.returncode != 0:
            print("  [FAIL] friTap import failed")
            return False

        # Test pytest availability
        result = self.run_command(
            [self.python_executable, "-m", "pytest", "--version"],
            "Testing pytest availability",
            capture_output=True,
        )

        if not result or result.returncode != 0:
            print("  [FAIL] pytest not available")
            return False

        # Run a quick test
        if not self.run_command(
            [self.python_executable, "dev/run_tests.py", "summary"],
            "Running test environment summary",
        ):
            print("  [WARN] Test runner validation failed")
            return False

        return True

    def create_vscode_config(self):
        """Create VS Code configuration for development."""
        print("[INFO] Creating VS Code configuration...")

        vscode_dir = self.root_dir / ".vscode"
        vscode_dir.mkdir(exist_ok=True)

        # Create settings.json
        settings = {
            "python.defaultInterpreterPath": "./venv/bin/python",
            "python.testing.pytestEnabled": True,
            "python.testing.pytestArgs": ["tests"],
            "python.linting.enabled": True,
            "python.linting.flake8Enabled": True,
            "python.formatting.provider": "black",
            "python.formatting.blackArgs": ["--line-length", "88"],
            "files.exclude": {
                "**/__pycache__": True,
                "**/*.pyc": True,
                "node_modules": True,
                ".coverage": True,
                "tests/coverage_html": True,
            },
        }

        settings_file = vscode_dir / "settings.json"
        if not settings_file.exists():
            with open(settings_file, "w") as f:
                json.dump(settings, f, indent=4)
            print("  [OK] Created .vscode/settings.json")
        else:
            print("  [OK] .vscode/settings.json already exists")

        # Create launch.json for debugging
        launch_config = {
            "version": "0.2.0",
            "configurations": [
                {
                    "name": "Run friTap Tests",
                    "type": "python",
                    "request": "launch",
                    "program": "${workspaceFolder}/dev/run_tests.py",
                    "args": ["unit"],
                    "console": "integratedTerminal",
                    "cwd": "${workspaceFolder}",
                },
                {
                    "name": "Debug friTap",
                    "type": "python",
                    "request": "launch",
                    "module": "friTap.friTap",
                    "args": ["--help"],
                    "console": "integratedTerminal",
                    "cwd": "${workspaceFolder}",
                },
            ],
        }

        launch_file = vscode_dir / "launch.json"
        if not launch_file.exists():
            with open(launch_file, "w") as f:
                json.dump(launch_config, f, indent=4)
            print("  [OK] Created .vscode/launch.json")
        else:
            print("  [OK] .vscode/launch.json already exists")

    def print_next_steps(self):
        """Print next steps for the developer."""
        print("\n[OK] Development environment setup complete!")
        print("\n[INFO] Next steps:")
        print("   1. Activate virtual environment (if not already active):")
        if self.platform == "windows":
            print("      venv\\Scripts\\activate")
        else:
            print("      source venv/bin/activate")

        print("\n   2. Run tests to verify setup:")
        print("      python dev/run_tests.py --fast")

        print("\n   3. Start developing:")
        print("      # Edit code in friTap/ or agent/")
        print("      # Run tests: python dev/run_tests.py unit")
        print("      # Compile agent: frida-compile agent/fritap_agent.ts -o friTap/fritap_agent.js")
        print("      # Format code: black friTap/ tests/")

        print("\n   4. Before committing:")
        print("      python dev/run_tests.py lint")
        print("      python dev/run_tests.py coverage")

        print("\n[INFO] Documentation:")
        print("   - Development Guide: DEVELOPMENT.md")
        print("   - Testing Guide: tests/README.md")
        print("   - Contributing: docs/development/contributing.md")

        print("\n[INFO] Need help?")
        print("   - Run: python dev/run_tests.py summary")
        print("   - Check: DEVELOPMENT.md")
        print("   - Issues: https://github.com/fkie-cad/friTap/issues")

    def setup(self):
        """Run complete development environment setup."""
        print("[INFO] friTap Development Environment Setup")
        print("=" * 50)

        success = True

        # Check prerequisites
        if not self.check_python_version():
            success = False

        self.check_git()  # Optional, don't fail setup

        if not success:
            print("\n[FAIL] Prerequisites not met. Please fix the issues above.")
            return False

        # Install dependencies
        if not self.install_python_dependencies():
            print("\n[FAIL] Failed to install Python dependencies")
            return False

        # Install frida-tools and validate frida-compile
        frida_tools_ok = self.install_frida_tools()
        if not frida_tools_ok:
            print("\n[WARN] frida-tools installation failed, but continuing...")

        frida_compile_ok = frida_tools_ok and self.setup_frida_compile()

        # Test agent compilation (only if frida-compile is available)
        if frida_compile_ok:
            if not self.test_agent_compilation():
                print("\n[WARN] Agent compilation test failed, but continuing...")

        # Setup development tools
        self.setup_pre_commit()  # Optional
        self.create_vscode_config()  # Optional

        # Optionally set up BoringSecretHunter
        self.setup_boringsecrethunter()

        # Validate setup
        if not self.validate_setup():
            print("\n[FAIL] Setup validation failed")
            return False

        self.print_next_steps()
        return True


def main():
    """Main entry point."""
    if "--help" in sys.argv or "-h" in sys.argv:
        print("""
friTap Development Environment Setup

Usage: python setup_dev.py [options]

Options:
  --help, -h    Show this help message

This script will:
  1. Check Python version (>= 3.10)
  2. Install Python development dependencies
  3. Install friTap in development mode
  4. Install frida-tools (provides frida-compile)
  5. Test agent compilation
  6. Setup pre-commit hooks (optional)
  7. Create VS Code configuration (optional)
  8. Setup BoringSecretHunter (if Docker is available)
  9. Validate the development setup
        """)
        return

    setup = FriTapDevSetup()

    try:
        success = setup.setup()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n[WARN] Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[FAIL] Unexpected error during setup: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
