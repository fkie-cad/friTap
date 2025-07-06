#!/usr/bin/env python3
"""
friTap Test Runner

Comprehensive test runner for friTap that handles different test categories
and provides detailed reporting.
"""

import sys
import subprocess
import argparse
import platform
from pathlib import Path


class FriTapTestRunner:
    """Test runner for friTap testing suite."""
    
    def __init__(self):
        self.root_dir = Path(__file__).parent
        self.test_dir = self.root_dir / "tests"
        self.platform = platform.system().lower()
        
    def run_unit_tests(self, verbose: bool = False) -> int:
        """Run unit tests."""
        print("🧪 Running Unit Tests")
        print("=" * 50)
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir / "unit"),
            "-m", "not slow",
            "--tb=short"
        ]
        
        if verbose:
            cmd.extend(["-v", "-s"])
        
        return subprocess.call(cmd)
    
    def run_agent_compilation_tests(self, verbose: bool = False) -> int:
        """Run agent compilation tests."""
        print("⚙️  Running Agent Compilation Tests")
        print("=" * 50)
        
        # Check if Node.js is available
        if not self._check_nodejs():
            print("❌ Node.js not available, skipping agent compilation tests")
            return 0
            
        cmd = [
            sys.executable, "-m", "pytest", 
            str(self.test_dir / "agent"),
            "-m", "agent_compilation",
            "--tb=short"
        ]
        
        if verbose:
            cmd.extend(["-v", "-s"])
            
        return subprocess.call(cmd)
    
    def run_mock_integration_tests(self, verbose: bool = False) -> int:
        """Run mock integration tests."""
        print("🔗 Running Mock Integration Tests") 
        print("=" * 50)
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir / "integration"),
            "-m", "mock_integration",
            "--tb=short"
        ]
        
        if verbose:
            cmd.extend(["-v", "-s"])
            
        return subprocess.call(cmd)
    
    def run_platform_specific_tests(self, verbose: bool = False) -> int:
        """Run platform-specific tests."""
        print(f"🖥️  Running {self.platform.title()} Platform Tests")
        print("=" * 50)
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir),
            "-m", self.platform,
            "--tb=short"
        ]
        
        if verbose:
            cmd.extend(["-v", "-s"])
            
        return subprocess.call(cmd)
    
    def run_ground_truth_tests(self, verbose: bool = False) -> int:
        """Run ground truth tests (requires built test applications)."""
        print("🎯 Running Ground Truth Tests")
        print("=" * 50)
        
        # Check if ground truth applications are built
        ground_truth_dir = self.root_dir / "ground_truth"
        if not self._check_ground_truth_apps(ground_truth_dir):
            print("⚠️  Ground truth applications not built, skipping tests")
            print("Run 'make all' in ground_truth/ directories to build test apps")
            return 0
            
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir),
            "-m", "ground_truth",
            "--tb=short",
            "--timeout=60"
        ]
        
        if verbose:
            cmd.extend(["-v", "-s"])
            
        return subprocess.call(cmd)
    
    def run_android_tests(self, verbose: bool = False) -> int:
        """Run Android-specific tests (requires connected device)."""
        print("📱 Running Android Tests")
        print("=" * 50)
        
        # Check if Android device is connected
        if not self._check_android_device():
            print("❌ No Android device connected, skipping Android tests")
            return 0
            
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir),
            "-m", "android",
            "--tb=short",
            "--timeout=120"
        ]
        
        if verbose:
            cmd.extend(["-v", "-s"])
            
        return subprocess.call(cmd)
    
    def run_all_tests(self, verbose: bool = False, fast: bool = False) -> int:
        """Run all applicable tests."""
        print("🚀 Running All friTap Tests")
        print("=" * 50)
        
        total_result = 0
        
        # Unit tests (always run)
        result = self.run_unit_tests(verbose)
        total_result += result
        print()
        
        # Agent compilation tests
        result = self.run_agent_compilation_tests(verbose)
        total_result += result
        print()
        
        # Mock integration tests
        result = self.run_mock_integration_tests(verbose)
        total_result += result
        print()
        
        if not fast:
            # Platform-specific tests
            result = self.run_platform_specific_tests(verbose)
            total_result += result
            print()
            
            # Ground truth tests (if available)
            result = self.run_ground_truth_tests(verbose)
            total_result += result
            print()
            
            # Android tests (if device available)
            result = self.run_android_tests(verbose)
            total_result += result
            print()
        
        return total_result
    
    def run_coverage_report(self) -> int:
        """Generate coverage report."""
        print("📊 Generating Coverage Report")
        print("=" * 50)
        
        cmd = [
            sys.executable, "-m", "pytest",
            str(self.test_dir / "unit"),
            str(self.test_dir / "integration"),
            "--cov=friTap",
            "--cov-report=html:tests/coverage_html",
            "--cov-report=term-missing",
            "--tb=no",
            "-q"
        ]
        
        result = subprocess.call(cmd)
        
        if result == 0:
            coverage_html = self.test_dir / "coverage_html" / "index.html"
            if coverage_html.exists():
                print(f"📈 Coverage report generated: {coverage_html}")
        
        return result
    
    def lint_tests(self) -> int:
        """Run linting on test code."""
        print("🔍 Linting Test Code")
        print("=" * 50)
        
        # Run flake8 on tests
        cmd = ["flake8", str(self.test_dir), "--max-line-length=88"]
        result = subprocess.call(cmd)
        
        if result == 0:
            print("✅ Test code linting passed")
        else:
            print("❌ Test code linting failed")
            
        return result
    
    def setup_test_environment(self) -> int:
        """Setup test environment and install dependencies."""
        print("🔧 Setting Up Test Environment")
        print("=" * 50)
        
        # Install test requirements
        requirements_file = self.test_dir / "requirements.txt"
        if requirements_file.exists():
            cmd = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
            result = subprocess.call(cmd)
            
            if result == 0:
                print("✅ Test dependencies installed")
            else:
                print("❌ Failed to install test dependencies")
                return result
        
        # Check friTap installation
        try:
            __import__('friTap')
            print("✅ friTap package available")
        except ImportError:
            print("❌ friTap package not installed")
            print("Install with: pip install -e .")
            return 1
        
        # Check Frida availability
        try:
            __import__('frida')
            print("✅ Frida available")
        except ImportError:
            print("⚠️  Frida not available - some tests will be skipped")
        
        return 0
    
    def _check_nodejs(self) -> bool:
        """Check if Node.js is available."""
        try:
            subprocess.run(["node", "--version"], 
                         capture_output=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _check_android_device(self) -> bool:
        """Check if Android device is connected."""
        try:
            result = subprocess.run(["adb", "devices"], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                return len(lines) > 1 and any('device' in line for line in lines[1:])
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False
    
    def _check_ground_truth_apps(self, ground_truth_dir: Path) -> bool:
        """Check if ground truth applications are built."""
        if not ground_truth_dir.exists():
            return False
            
        # Check for Linux ground truth apps
        linux_dir = ground_truth_dir / "example_app_linux"
        if linux_dir.exists():
            executables = ["openssl_impl", "nss_impl", "gnutls_impl"]
            if any((linux_dir / exe).exists() for exe in executables):
                return True
        
        # Check for Android ground truth apps
        android_dir = ground_truth_dir / "example_app_android"
        if android_dir.exists():
            apk_path = android_dir / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
            if apk_path.exists():
                return True
        
        return False
    
    def print_test_summary(self):
        """Print test environment summary."""
        print("🔍 friTap Test Environment Summary")
        print("=" * 50)
        print(f"Platform: {platform.system()} {platform.release()}")
        print(f"Python: {sys.version}")
        print(f"Test directory: {self.test_dir}")
        
        # Check dependencies
        dependencies = [
            ("pytest", "pytest"),
            ("frida", "frida"),
            ("node", "Node.js"),
            ("adb", "Android Debug Bridge")
        ]
        
        for cmd, name in dependencies:
            try:
                if cmd == "pytest":
                    import pytest
                    print(f"✅ {name}: {pytest.__version__}")
                elif cmd == "frida":
                    import frida
                    print(f"✅ {name}: {frida.__version__}")
                elif cmd in ["node", "adb"]:
                    result = subprocess.run([cmd, "--version"], 
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        version = result.stdout.strip().split('\n')[0]
                        print(f"✅ {name}: {version}")
                    else:
                        print(f"❌ {name}: Not available")
            except (ImportError, FileNotFoundError, subprocess.TimeoutExpired):
                print(f"❌ {name}: Not available")
        
        print()


def main():
    """Main entry point for test runner."""
    parser = argparse.ArgumentParser(description="friTap Test Runner")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--fast", action="store_true",
                       help="Run only fast tests (unit + mock integration)")
    
    subparsers = parser.add_subparsers(dest="command", help="Test commands")
    
    # Test type commands
    subparsers.add_parser("unit", help="Run unit tests")
    subparsers.add_parser("agent", help="Run agent compilation tests")
    subparsers.add_parser("integration", help="Run mock integration tests")
    subparsers.add_parser("platform", help="Run platform-specific tests")
    subparsers.add_parser("ground-truth", help="Run ground truth tests")
    subparsers.add_parser("android", help="Run Android tests")
    subparsers.add_parser("all", help="Run all tests")
    
    # Utility commands
    subparsers.add_parser("coverage", help="Generate coverage report")
    subparsers.add_parser("lint", help="Lint test code")
    subparsers.add_parser("setup", help="Setup test environment")
    subparsers.add_parser("summary", help="Show test environment summary")
    
    args = parser.parse_args()
    
    runner = FriTapTestRunner()
    
    if args.command == "unit":
        return runner.run_unit_tests(args.verbose)
    elif args.command == "agent":
        return runner.run_agent_compilation_tests(args.verbose)
    elif args.command == "integration":
        return runner.run_mock_integration_tests(args.verbose)
    elif args.command == "platform":
        return runner.run_platform_specific_tests(args.verbose)
    elif args.command == "ground-truth":
        return runner.run_ground_truth_tests(args.verbose)
    elif args.command == "android":
        return runner.run_android_tests(args.verbose)
    elif args.command == "all":
        return runner.run_all_tests(args.verbose, args.fast)
    elif args.command == "coverage":
        return runner.run_coverage_report()
    elif args.command == "lint":
        return runner.lint_tests()
    elif args.command == "setup":
        return runner.setup_test_environment()
    elif args.command == "summary":
        runner.print_test_summary()
        return 0
    else:
        # Default: run all tests
        runner.print_test_summary()
        return runner.run_all_tests(args.verbose, args.fast)


if __name__ == "__main__":
    sys.exit(main())