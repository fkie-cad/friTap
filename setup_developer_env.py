#!/usr/bin/env python3
"""
friTap Developer Environment Setup Script

This script sets up a complete development environment for friTap,
including all dependencies for TypeScript agent development.
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path


def run_command(cmd, description="", check=True):
    """Run a command and handle errors gracefully"""
    print(f"\n🔧 {description}")
    print(f"💻 Running: {cmd}")
    
    try:
        result = subprocess.run(cmd, shell=True, check=check, capture_output=True, text=True)
        if result.stdout:
            print(f"✅ {result.stdout.strip()}")
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        if e.stderr:
            print(f"💥 stderr: {e.stderr.strip()}")
        return False


def check_command_exists(command):
    """Check if a command exists in PATH"""
    return shutil.which(command) is not None


def detect_platform():
    """Detect the operating system"""
    system = platform.system().lower()
    if system == "darwin":
        return "macOS"
    elif system == "linux":
        return "Linux"
    elif system == "windows":
        return "Windows"
    else:
        return "Unknown"


def setup_python_environment():
    """Set up Python development environment"""
    print("\n🐍 Setting up Python Development Environment")
    
    # Check Python version
    python_version = sys.version_info
    if python_version < (3, 7):
        print("❌ Python 3.7+ is required")
        return False
    
    print(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro} detected")
    
    # Install friTap in development mode
    if not run_command("pip install -e .", "Installing friTap in development mode"):
        return False
    
    # Install development dependencies
    if not run_command("pip install -r requirements-dev.txt", "Installing development dependencies"):
        return False
    
    print("✅ Python environment setup complete")
    return True


def setup_nodejs_environment():
    """Set up Node.js environment for TypeScript compilation"""
    print("\n📦 Setting up Node.js Environment")
    
    # Check if Node.js is installed
    if not check_command_exists("node"):
        print("❌ Node.js is not installed")
        print("🔗 Please install Node.js from: https://nodejs.org/")
        print("🔗 Or use a package manager:")
        
        system = detect_platform()
        if system == "macOS":
            print("   brew install node")
        elif system == "Linux":
            print("   sudo apt-get install nodejs npm  # Ubuntu/Debian")
            print("   sudo yum install nodejs npm      # CentOS/RHEL")
        elif system == "Windows":
            print("   Download from https://nodejs.org/")
        
        return False
    
    # Check Node.js version
    result = subprocess.run("node --version", shell=True, capture_output=True, text=True)
    node_version = result.stdout.strip()
    print(f"✅ Node.js {node_version} detected")
    
    # Check npm
    if not check_command_exists("npm"):
        print("❌ npm is not installed")
        return False
    
    # Install npm dependencies
    if not run_command("npm install", "Installing Node.js dependencies"):
        return False
    
    print("✅ Node.js environment setup complete")
    return True


def setup_frida_compile():
    """Set up frida-compile from frida-tools"""
    print("\n🔧 Setting up frida-compile")
    
    # Install frida-tools to get latest frida-compile
    if not run_command("pip install --upgrade frida-tools", "Installing/upgrading frida-tools"):
        return False
    
    # Verify frida-compile is available
    if not check_command_exists("frida-compile"):
        print("❌ frida-compile not found after installing frida-tools")
        print("🔍 You may need to add frida-tools to your PATH")
        return False
    
    # Check frida-compile version
    result = subprocess.run("frida-compile --version", shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"✅ frida-compile {result.stdout.strip()} available")
    else:
        print("⚠️  frida-compile installed but version check failed")
    
    print("✅ frida-compile setup complete")
    return True


def test_agent_compilation():
    """Test TypeScript agent compilation"""
    print("\n🧪 Testing Agent Compilation")
    
    # Test compilation using npm script
    if not run_command("npm run build", "Testing TypeScript compilation"):
        print("❌ Agent compilation failed")
        print("🔍 Check that all TypeScript files are valid")
        return False
    
    # Check if compiled files exist
    ssl_log_js = Path("friTap/_ssl_log.js")
    ssl_log_legacy_js = Path("friTap/_ssl_log_legacy.js")
    
    if ssl_log_js.exists() and ssl_log_legacy_js.exists():
        print("✅ Agent compilation successful")
        print(f"📁 Generated: {ssl_log_js}")
        print(f"📁 Generated: {ssl_log_legacy_js}")
        return True
    else:
        print("❌ Compiled agent files not found")
        return False


def setup_testing_environment():
    """Set up testing environment"""
    print("\n🧪 Setting up Testing Environment")
    
    # Install test dependencies (should be in requirements-dev.txt)
    if not run_command("pip install pytest pytest-cov", "Installing core testing tools"):
        return False
    
    # Test that tests can run
    if not run_command("python run_tests.py summary", "Testing framework check"):
        print("⚠️  Test framework check failed - this is expected if no tests exist yet")
    
    print("✅ Testing environment setup complete")
    return True


def setup_pre_commit_hooks():
    """Set up pre-commit hooks"""
    print("\n🔗 Setting up Pre-commit Hooks")
    
    # Install pre-commit if not already installed
    if not run_command("pip install pre-commit", "Installing pre-commit"):
        return False
    
    # Install hooks
    if not run_command("pre-commit install", "Installing pre-commit hooks"):
        print("⚠️  Pre-commit hook installation failed - this is optional")
        return True
    
    print("✅ Pre-commit hooks setup complete")
    return True


def setup_boringsecrethunter():
    """Set up BoringSecretHunter Docker environment"""
    print("\n🔍 Setting up BoringSecretHunter Environment")
    
    # Check if Docker is available
    if not check_command_exists("docker"):
        print("❌ Docker is not installed")
        print("🔗 Please install Docker from: https://docker.com/")
        print("🔗 BoringSecretHunter requires Docker for the best experience")
        return False
    
    print("✅ Docker detected")
    
    # Create directories for BoringSecretHunter
    os.makedirs("binary", exist_ok=True)
    os.makedirs("results", exist_ok=True)
    print("✅ Created binary/ and results/ directories for BoringSecretHunter")
    
    # Test Docker access
    if not run_command("docker info", "Testing Docker access", check=False):
        print("⚠️  Docker access test failed - you may need to start Docker daemon")
        print("💡 BoringSecretHunter will be available once Docker is running")
        return True
    
    print("✅ BoringSecretHunter environment ready")
    print("💡 Usage: docker run --rm -v \"$(pwd)/binary\":/usr/local/src/binaries -v \"$(pwd)/results\":/host_output boringsecrethunter")
    return True


def print_summary(success_steps, failed_steps):
    """Print setup summary"""
    print("\n" + "="*60)
    print("🏁 DEVELOPMENT ENVIRONMENT SETUP SUMMARY")
    print("="*60)
    
    if success_steps:
        print("\n✅ Successfully completed:")
        for step in success_steps:
            print(f"   ✓ {step}")
    
    if failed_steps:
        print("\n❌ Failed steps:")
        for step in failed_steps:
            print(f"   ✗ {step}")
        print("\n💡 Please resolve the failed steps manually")
    
    print("\n📚 Next Steps:")
    print("   1. Test agent compilation: npm run build")
    print("   2. Run tests: python run_tests.py")
    print("   3. Start developing: edit files in agent/")
    print("   4. Generate patterns: use BoringSecretHunter Docker")
    
    print("\n📖 Documentation:")
    print("   • Development Guide: DEVELOPMENT.md")
    print("   • TypeScript API: See updated DEVELOPMENT.md")
    print("   • Testing: tests/README.md")
    
    if not failed_steps:
        print("\n🎉 Development environment setup complete!")
        return True
    else:
        print(f"\n⚠️  Setup completed with {len(failed_steps)} issues")
        return False


def main():
    """Main setup function"""
    print("🚀 friTap Developer Environment Setup")
    print("=====================================")
    print(f"🖥️  Platform: {detect_platform()}")
    print(f"🐍 Python: {sys.version}")
    
    success_steps = []
    failed_steps = []
    
    # Setup steps
    steps = [
        ("Python Environment", setup_python_environment),
        ("Node.js Environment", setup_nodejs_environment),
        ("frida-compile", setup_frida_compile),
        ("Agent Compilation Test", test_agent_compilation),
        ("Testing Environment", setup_testing_environment),
        ("Pre-commit Hooks", setup_pre_commit_hooks),
        ("BoringSecretHunter", setup_boringsecrethunter),
    ]
    
    for step_name, step_function in steps:
        try:
            if step_function():
                success_steps.append(step_name)
            else:
                failed_steps.append(step_name)
        except Exception as e:
            print(f"❌ Unexpected error in {step_name}: {e}")
            failed_steps.append(step_name)
    
    # Print summary
    return print_summary(success_steps, failed_steps)


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n🛑 Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        sys.exit(1)