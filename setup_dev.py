#!/usr/bin/env python3
"""
friTap Development Environment Setup Script

Automated setup script for friTap development environment.
Handles dependency installation, environment configuration, and validation.
"""

import os
import sys
import subprocess
import platform
import venv
from pathlib import Path


class FriTapDevSetup:
    """Automated development environment setup for friTap."""
    
    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.platform = platform.system().lower()
        self.python_executable = sys.executable
        
    def run_command(self, cmd, description="", check=True, capture_output=False):
        """Run a command with error handling."""
        print(f"🔧 {description}")
        try:
            if isinstance(cmd, str):
                cmd = cmd.split()
            
            result = subprocess.run(
                cmd, 
                check=check, 
                capture_output=capture_output,
                text=True,
                cwd=self.root_dir
            )
            
            if capture_output:
                return result
            else:
                print("✅ Success")
                return True
                
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed: {e}")
            if capture_output:
                print(f"   stdout: {e.stdout}")
                print(f"   stderr: {e.stderr}")
            return False
        except FileNotFoundError as e:
            print(f"❌ Command not found: {e}")
            return False
    
    def check_python_version(self):
        """Check Python version compatibility."""
        print("🐍 Checking Python version...")
        
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 7):
            print(f"❌ Python {version.major}.{version.minor} is not supported")
            print("   friTap requires Python 3.7 or later")
            return False
        
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} is supported")
        return True
    
    def check_node_js(self):
        """Check Node.js availability."""
        print("📦 Checking Node.js...")
        
        result = self.run_command(
            ["node", "--version"], 
            "Checking Node.js version",
            check=False,
            capture_output=True
        )
        
        if not result or result.returncode != 0:
            print("⚠️  Node.js not found")
            print("   TypeScript agent compilation will not be available")
            print("   Install Node.js from: https://nodejs.org/")
            return False
        
        version = result.stdout.strip()
        print(f"✅ Node.js {version} found")
        return True
    
    def check_git(self):
        """Check Git availability."""
        print("📚 Checking Git...")
        
        result = self.run_command(
            ["git", "--version"],
            "Checking Git version", 
            check=False,
            capture_output=True
        )
        
        if not result or result.returncode != 0:
            print("⚠️  Git not found")
            print("   Git is recommended for development")
            return False
        
        version = result.stdout.strip()
        print(f"✅ {version}")
        return True
    
    def install_python_dependencies(self):
        """Install Python development dependencies."""
        print("📦 Installing Python dependencies...")
        
        # Install development dependencies
        if not self.run_command(
            [self.python_executable, "-m", "pip", "install", "-r", "requirements-dev.txt"],
            "Installing development dependencies"
        ):
            return False
        
        # Install friTap in development mode
        if not self.run_command(
            [self.python_executable, "-m", "pip", "install", "-e", "."],
            "Installing friTap in development mode"
        ):
            return False
        
        return True
    
    def install_node_dependencies(self):
        """Install Node.js dependencies."""
        if not self.check_node_js():
            print("⏭️  Skipping Node.js dependencies (Node.js not available)")
            return True
        
        print("📦 Installing Node.js dependencies...")
        
        # Check if package.json exists
        package_json = self.root_dir / "package.json"
        if not package_json.exists():
            print("⚠️  package.json not found, skipping Node.js setup")
            return True
        
        # Install Node.js dependencies
        if not self.run_command(
            ["npm", "install"],
            "Installing TypeScript dependencies"
        ):
            return False
        
        # Test agent compilation
        compile_script = self.root_dir / "compile_agent.sh"
        if compile_script.exists():
            if not self.run_command(
                ["./compile_agent.sh"],
                "Testing agent compilation"
            ):
                print("⚠️  Agent compilation test failed")
                return False
        
        return True
    
    def setup_pre_commit(self):
        """Setup pre-commit hooks."""
        print("🔗 Setting up pre-commit hooks...")
        
        # Check if pre-commit is available
        result = self.run_command(
            [self.python_executable, "-m", "pre_commit", "--version"],
            "Checking pre-commit availability",
            check=False,
            capture_output=True
        )
        
        if not result or result.returncode != 0:
            print("⚠️  pre-commit not available, skipping hooks setup")
            return True
        
        # Install pre-commit hooks
        if not self.run_command(
            [self.python_executable, "-m", "pre_commit", "install"],
            "Installing pre-commit hooks"
        ):
            print("⚠️  Failed to install pre-commit hooks")
            return False
        
        return True
    
    def validate_setup(self):
        """Validate the development setup."""
        print("🔍 Validating development setup...")
        
        # Test friTap import
        result = self.run_command(
            [self.python_executable, "-c", "import friTap; print('friTap import: OK')"],
            "Testing friTap import",
            capture_output=True
        )
        
        if not result or result.returncode != 0:
            print("❌ friTap import failed")
            return False
        
        # Test pytest availability
        result = self.run_command(
            [self.python_executable, "-m", "pytest", "--version"],
            "Testing pytest availability",
            capture_output=True
        )
        
        if not result or result.returncode != 0:
            print("❌ pytest not available")
            return False
        
        # Run a quick test
        if not self.run_command(
            [self.python_executable, "run_tests.py", "summary"],
            "Running test environment summary"
        ):
            print("⚠️  Test runner validation failed")
            return False
        
        return True
    
    def create_vscode_config(self):
        """Create VS Code configuration for development."""
        print("⚙️  Creating VS Code configuration...")
        
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
                "tests/coverage_html": True
            }
        }
        
        settings_file = vscode_dir / "settings.json"
        if not settings_file.exists():
            import json
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
            print("✅ Created .vscode/settings.json")
        else:
            print("✅ .vscode/settings.json already exists")
        
        # Create launch.json for debugging
        launch_config = {
            "version": "0.2.0",
            "configurations": [
                {
                    "name": "Run friTap Tests",
                    "type": "python",
                    "request": "launch",
                    "program": "${workspaceFolder}/run_tests.py",
                    "args": ["unit"],
                    "console": "integratedTerminal",
                    "cwd": "${workspaceFolder}"
                },
                {
                    "name": "Debug friTap",
                    "type": "python", 
                    "request": "launch",
                    "module": "friTap.friTap",
                    "args": ["--help"],
                    "console": "integratedTerminal",
                    "cwd": "${workspaceFolder}"
                }
            ]
        }
        
        launch_file = vscode_dir / "launch.json"
        if not launch_file.exists():
            import json
            with open(launch_file, 'w') as f:
                json.dump(launch_config, f, indent=4)
            print("✅ Created .vscode/launch.json")
        else:
            print("✅ .vscode/launch.json already exists")
    
    def print_next_steps(self):
        """Print next steps for the developer."""
        print("\n🎉 Development environment setup complete!")
        print("\n📋 Next steps:")
        print("   1. Activate virtual environment (if not already active):")
        if self.platform == "windows":
            print("      venv\\Scripts\\activate")
        else:
            print("      source venv/bin/activate")
        
        print("\n   2. Run tests to verify setup:")
        print("      python run_tests.py --fast")
        
        print("\n   3. Start developing:")
        print("      # Edit code in friTap/ or agent/")
        print("      # Run tests: python run_tests.py unit")
        print("      # Compile agent: npm run build")
        print("      # Format code: black friTap/ tests/")
        
        print("\n   4. Before committing:")
        print("      python run_tests.py lint")
        print("      python run_tests.py coverage")
        
        print("\n📖 Documentation:")
        print("   • Development Guide: DEVELOPMENT.md")
        print("   • Testing Guide: tests/README.md")
        print("   • Contributing: docs/development/contributing.md")
        
        print("\n🆘 Need help?")
        print("   • Run: python run_tests.py summary")
        print("   • Check: DEVELOPMENT.md")
        print("   • Issues: https://github.com/fkie-cad/friTap/issues")
    
    def setup(self):
        """Run complete development environment setup."""
        print("🚀 friTap Development Environment Setup")
        print("=" * 50)
        
        success = True
        
        # Check prerequisites
        if not self.check_python_version():
            success = False
        
        self.check_git()  # Optional, don't fail setup
        node_available = self.check_node_js()  # Optional for core functionality
        
        if not success:
            print("\n❌ Prerequisites not met. Please fix the issues above.")
            return False
        
        # Install dependencies
        if not self.install_python_dependencies():
            print("\n❌ Failed to install Python dependencies")
            return False
        
        if node_available:
            if not self.install_node_dependencies():
                print("\n⚠️  Node.js setup failed, but continuing...")
        
        # Setup development tools
        self.setup_pre_commit()  # Optional
        self.create_vscode_config()  # Optional
        
        # Validate setup
        if not self.validate_setup():
            print("\n❌ Setup validation failed")
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
  --minimal     Skip optional components (Node.js, pre-commit, VS Code)

This script will:
  1. Check Python and Node.js versions
  2. Install Python development dependencies  
  3. Install friTap in development mode
  4. Install Node.js dependencies (if available)
  5. Setup pre-commit hooks (optional)
  6. Create VS Code configuration (optional)
  7. Validate the development setup
        """)
        return
    
    setup = FriTapDevSetup()
    
    try:
        success = setup.setup()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error during setup: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()