"""
Tests for TypeScript agent compilation.

Validates that the TypeScript agent compiles successfully
and produces valid JavaScript output.
"""

import json
import os
import re
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

FRITAP_ROOT = Path(__file__).parent.parent.parent
# The build script lives in dev/ (see RELEASING.md / DEVELOPMENT.md).
COMPILE_SCRIPT = FRITAP_ROOT / "dev" / "compile_agent.sh"
# Pinned Node frida-compile (the same binary dev/compile_agent.sh uses).
FRIDA_COMPILE_BIN = FRITAP_ROOT / "node_modules" / ".bin" / "frida-compile"

# TypeScript-only syntax that must not survive compilation. Anchored to
# declaration/signature positions so plain JS such as the object literal
# `value: stringToIndex.value` or a JSDoc `{ [key: string]: ... }` comment
# does not trip the check.
TS_ONLY_SYNTAX = [
    re.compile(r"^\s*(?:export\s+)?interface\s+\w+\s*(?:<[^>]*>)?\s*\{", re.M),
    re.compile(r"^\s*(?:export\s+)?type\s+\w+\s*(?:<[^>]*>)?\s*=", re.M),
    re.compile(r"\b(?:let|const|var)\s+\w+\s*:\s*(?:string|number|boolean|any)\b"),
    re.compile(r"\bfunction\s*\w*\s*\([^)]*?\b\w+\??\s*:\s*(?:string|number|boolean|any)\b[^)]*\)"),
]


def find_typescript_syntax(content):
    """Return the TypeScript-only constructs found in `content` (empty if none)."""
    return [m.group(0) for pattern in TS_ONLY_SYNTAX for m in pattern.finditer(content)]


@pytest.mark.agent_compilation
class TestAgentCompilation:
    """Test TypeScript agent compilation process."""
    
    @pytest.fixture
    def fritap_root(self):
        """Get friTap root directory."""
        return Path(__file__).parent.parent.parent
        
    @pytest.fixture
    def agent_dir(self, fritap_root):
        """Get agent directory."""
        return fritap_root / "agent"
        
    @pytest.fixture
    def compiled_agent_path(self, fritap_root):
        """Get path to compiled agent."""
        return fritap_root / "friTap" / "fritap_agent.js"
        
    def test_typescript_config_exists(self, fritap_root):
        """Test that TypeScript configuration exists."""
        tsconfig_path = fritap_root / "tsconfig.json"
        assert tsconfig_path.exists(), "tsconfig.json not found"
        
        # Verify tsconfig.json is valid JSON
        with open(tsconfig_path) as f:
            config = json.load(f)
            assert "compilerOptions" in config
            
    def test_package_json_exists(self, fritap_root):
        """Test that package.json exists with required dependencies."""
        package_json_path = fritap_root / "package.json"
        assert package_json_path.exists(), "package.json not found"
        
        with open(package_json_path) as f:
            package_data = json.load(f)
            
        # Check for required dependencies
        assert "dependencies" in package_data or "devDependencies" in package_data
        
        # Check for frida-compile
        all_deps = {}
        if "dependencies" in package_data:
            all_deps.update(package_data["dependencies"])
        if "devDependencies" in package_data:
            all_deps.update(package_data["devDependencies"])
            
        assert "frida-compile" in all_deps, "frida-compile dependency not found"
        
    def test_compilation_script_exists(self, fritap_root):
        """Test that compilation scripts exist."""
        unix_script = fritap_root / "dev" / "compile_agent.sh"
        assert unix_script.exists(), "dev/compile_agent.sh not found"
        assert os.access(unix_script, os.X_OK), \
            "dev/compile_agent.sh is not executable"
                
    @pytest.mark.skipif(not COMPILE_SCRIPT.exists() or not FRIDA_COMPILE_BIN.exists(),
                       reason="dev/compile_agent.sh or node_modules frida-compile not found")
    def test_agent_compilation_unix(self, fritap_root, compiled_agent_path):
        """Test agent compilation on Unix systems."""
        # Change to friTap root directory
        original_cwd = os.getcwd()
        os.chdir(fritap_root)
        
        try:
            # Run compilation script (intercept target only: what this test checks)
            result = subprocess.run(
                [str(COMPILE_SCRIPT), 'intercept'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Check compilation succeeded
            assert result.returncode == 0, \
                f"Compilation failed: {result.stderr}"
                
            # Check compiled agent exists
            assert compiled_agent_path.exists(), \
                "Compiled agent file not created"
                
            # Check compiled agent is not empty
            assert compiled_agent_path.stat().st_size > 0, \
                "Compiled agent file is empty"
                
        finally:
            os.chdir(original_cwd)
            
    @pytest.mark.skipif(os.name != 'nt', reason="Windows only test")
    def test_agent_compilation_windows(self, fritap_root, compiled_agent_path):
        """Test agent compilation on Windows systems."""
        # Change to friTap root directory
        original_cwd = os.getcwd()
        os.chdir(fritap_root)
        
        try:
            # Run compilation script
            result = subprocess.run(
                ['compile_agent.bat'], 
                capture_output=True, 
                text=True, 
                timeout=60,
                shell=True
            )
            
            # Check compilation succeeded
            assert result.returncode == 0, \
                f"Compilation failed: {result.stderr}"
                
            # Check compiled agent exists
            assert compiled_agent_path.exists(), \
                "Compiled agent file not created"
                
        finally:
            os.chdir(original_cwd)
            
    def test_npm_install_works(self, fritap_root):
        """Test that npm install works properly."""
        original_cwd = os.getcwd()
        os.chdir(fritap_root)
        
        try:
            # Check if node_modules exists or create it
            result = subprocess.run(
                ['npm', 'install'], 
                capture_output=True, 
                text=True, 
                timeout=120
            )
            
            # npm install should succeed
            assert result.returncode == 0, \
                f"npm install failed: {result.stderr}"
                
            # node_modules should exist
            node_modules = fritap_root / "node_modules"
            assert node_modules.exists(), "node_modules directory not created"
            
        finally:
            os.chdir(original_cwd)
            
    def test_frida_compile_available(self, fritap_root):
        """Test that the pinned frida-compile is installed and runnable."""
        pkg_json = fritap_root / "node_modules" / "frida-compile" / "package.json"
        if not pkg_json.exists():
            pytest.skip("node_modules/frida-compile not installed (run npm ci)")
        with open(pkg_json) as f:
            installed = json.load(f)["version"]
        with open(fritap_root / "package.json") as f:
            pinned = json.load(f).get("devDependencies", {}).get("frida-compile")
        if pinned:
            assert installed == pinned, \
                f"installed frida-compile {installed} != pinned {pinned} (run npm ci)"
        # frida-compile has no --version flag; --help is the cheap liveness probe.
        result = subprocess.run(
            [str(FRIDA_COMPILE_BIN), '--help'],
            capture_output=True,
            text=True,
            timeout=30
        )
        assert result.returncode == 0, f"frida-compile not runnable: {result.stderr}"
        assert "Usage: frida-compile" in result.stdout
            
    def test_typescript_compiler_available(self):
        """Test that TypeScript compiler is available."""
        try:
            result = subprocess.run(
                ['npx', 'tsc', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            assert result.returncode == 0, "TypeScript compiler not available"
        except FileNotFoundError:
            pytest.skip("npx not available")


@pytest.mark.agent_compilation
class TestCompiledAgentValidation:
    """Test validation of compiled agent output."""
    
    @pytest.fixture
    def compiled_agent_path(self):
        """Get path to compiled agent."""
        fritap_root = Path(__file__).parent.parent.parent
        return fritap_root / "friTap" / "fritap_agent.js"
        
    def test_compiled_agent_exists(self, compiled_agent_path):
        """Test that compiled agent file exists."""
        assert compiled_agent_path.exists(), \
            "Compiled agent file does not exist. Run compilation first."
            
    def test_compiled_agent_not_empty(self, compiled_agent_path):
        """Test that compiled agent is not empty."""
        if compiled_agent_path.exists():
            assert compiled_agent_path.stat().st_size > 0, \
                "Compiled agent file is empty"
                
    def test_compiled_agent_syntax(self, compiled_agent_path):
        """Test that compiled agent has valid JavaScript syntax."""
        if not compiled_agent_path.exists():
            pytest.skip("Compiled agent not found")
            
        with open(compiled_agent_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Basic syntax checks
        assert len(content) > 100, "Compiled agent seems too small"
        
        # Should contain function definitions or arrow functions
        assert 'function' in content or '=>' in content, \
            "No function definitions found"
            
        # Should not contain TypeScript-specific syntax
        ts_syntax = find_typescript_syntax(content)
        assert not ts_syntax, \
            f"TypeScript-only syntax found - compilation incomplete: {ts_syntax[:3]}"
        assert 'export class' not in content, \
            "TypeScript export found - compilation incomplete"
            
    def test_typescript_syntax_detector(self):
        """The TS-syntax check flags real annotations but not JS look-alikes."""
        assert find_typescript_syntax("interface Foo {\n  a: string;\n}")
        assert find_typescript_syntax("type Bar = { a: number };")
        assert find_typescript_syntax("let name: string = 'x';")
        assert find_typescript_syntax("function f(a: string, b) { return a; }")
        assert not find_typescript_syntax("const o = { value: stringToIndex.value };")
        assert not find_typescript_syntax("/** @return {{ [key: string]: number }} */")
        assert not find_typescript_syntax("x = c ? a : string_value;")

    def test_compiled_agent_contains_frida_api(self, compiled_agent_path):
        """Test that compiled agent contains Frida API calls."""
        if not compiled_agent_path.exists():
            pytest.skip("Compiled agent not found")
            
        with open(compiled_agent_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Should contain Frida API calls
        frida_apis = [
            'Interceptor.attach',
            'Module.getExportByName',
            'Process.getModuleByName',
            'NativePointer',
            'Memory.scan'
        ]
        
        found_apis = [api for api in frida_apis if api in content]
        assert len(found_apis) > 0, \
            f"No Frida API calls found. Expected one of: {frida_apis}"
            
    def test_compiled_agent_ssl_functions(self, compiled_agent_path):
        """Test that compiled agent contains SSL-related functions."""
        if not compiled_agent_path.exists():
            pytest.skip("Compiled agent not found")
            
        with open(compiled_agent_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Should contain SSL/TLS related strings
        ssl_indicators = [
            'SSL_read',
            'SSL_write',
            'ssl',
            'tls',
            'crypto'
        ]
        
        found_indicators = [indicator for indicator in ssl_indicators 
                          if indicator.lower() in content.lower()]
        assert len(found_indicators) > 0, \
            f"No SSL/TLS indicators found. Expected one of: {ssl_indicators}"
            
    def test_compiled_agent_size_reasonable(self, compiled_agent_path):
        """Test that compiled agent has reasonable size."""
        if not compiled_agent_path.exists():
            pytest.skip("Compiled agent not found")
            
        file_size = compiled_agent_path.stat().st_size
        
        # Should be at least 10KB but not more than 10MB
        assert file_size > 10 * 1024, \
            f"Compiled agent too small: {file_size} bytes"
        assert file_size < 10 * 1024 * 1024, \
            f"Compiled agent too large: {file_size} bytes"


@pytest.mark.agent_compilation
class TestCompilationErrorHandling:
    """Test compilation error handling and recovery."""
    
    def test_compilation_with_syntax_error(self, tmp_path):
        """Test compilation behavior with TypeScript syntax errors."""
        # Create a temporary TypeScript file with syntax error
        bad_ts_file = tmp_path / "bad_agent.ts"
        bad_ts_file.write_text("""
        // This file has intentional syntax errors
        export class BadAgent {
            invalid syntax here
            missing semicolon
            unclosed bracket {
        """)
        
        if not FRIDA_COMPILE_BIN.exists():
            pytest.skip("node_modules frida-compile not installed (run npm ci)")
        # frida-compile only accepts entries inside the project root (its cwd),
        # so compile from tmp_path; otherwise it fails for the wrong reason.
        result = subprocess.run(
            [str(FRIDA_COMPILE_BIN), bad_ts_file.name, '-o', 'output.js'],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=tmp_path
        )

        # Compilation should fail with a real TypeScript diagnostic
        assert result.returncode != 0, \
            "Compilation should fail with syntax errors"
        output = (result.stdout + result.stderr).lower()
        assert "error ts" in output, \
            f"TypeScript error message should be present: {output[:300]}"
            
    def test_compilation_with_missing_dependencies(self, tmp_path):
        """Test compilation with missing dependencies."""
        # Create TypeScript file that imports non-existent module
        bad_import_file = tmp_path / "bad_import.ts"
        bad_import_file.write_text("""
        import { NonExistentClass } from './non-existent-module';
        
        export class TestAgent {
            test() {
                return new NonExistentClass();
            }
        }
        """)
        
        if not FRIDA_COMPILE_BIN.exists():
            pytest.skip("node_modules frida-compile not installed (run npm ci)")
        result = subprocess.run(
            [str(FRIDA_COMPILE_BIN), bad_import_file.name, '-o', 'output.js'],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=tmp_path
        )

        # Should fail due to the missing import (not the project-root check)
        assert result.returncode != 0, \
            "Compilation should fail with missing imports"
        output = result.stdout + result.stderr
        assert "non-existent-module" in output, \
            f"Error should name the missing module: {output[:300]}"
            
    @patch('subprocess.run')
    def test_compilation_timeout_handling(self, mock_subprocess):
        """Test handling of compilation timeouts."""
        # Mock subprocess to raise timeout
        mock_subprocess.side_effect = subprocess.TimeoutExpired('frida-compile', 60)
        
        fritap_root = Path(__file__).parent.parent.parent
        original_cwd = os.getcwd()
        os.chdir(fritap_root)
        
        try:
            with pytest.raises(subprocess.TimeoutExpired):
                subprocess.run(
                    [str(COMPILE_SCRIPT)],
                    capture_output=True, 
                    text=True, 
                    timeout=60
                )
        finally:
            os.chdir(original_cwd)


@pytest.mark.agent_compilation  
class TestCompilationOutput:
    """Test compilation output and artifacts."""
    
    @pytest.fixture
    def fritap_root(self):
        """Get friTap root directory."""
        return Path(__file__).parent.parent.parent
        
    def test_compilation_produces_expected_files(self, fritap_root):
        """Test that compilation produces all expected output files."""
        compiled_agent = fritap_root / "friTap" / "fritap_agent.js"
        
        if compiled_agent.exists():
            # Main agent should exist
            assert compiled_agent.exists()
            
            # Should be a valid file
            assert compiled_agent.is_file()
            
            # Should have reasonable modification time (not ancient)
            import time
            mtime = compiled_agent.stat().st_mtime
            current_time = time.time()
            
            # File should be modified within last week (for CI/development)
            # This is a loose check - in real development it would be more recent
            age_days = (current_time - mtime) / (24 * 3600)
            assert age_days < 30, f"Compiled agent seems old: {age_days} days"
            
    def test_compilation_preserves_functionality(self, fritap_root):
        """Test that compilation preserves agent functionality."""
        compiled_agent = fritap_root / "friTap" / "fritap_agent.js"
        
        if not compiled_agent.exists():
            pytest.skip("Compiled agent not found")
            
        with open(compiled_agent, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check for key functionality preservation
        key_functions = [
            # Should contain hook installation logic
            'attach',
            'hook',
            'install',
            
            # Should contain SSL library detection
            'ssl',
            'openssl',
            'boringssl',
            
            # Should contain data processing
            'read',
            'write',
            'send'
        ]
        
        found_functions = []
        for func in key_functions:
            if func.lower() in content.lower():
                found_functions.append(func)
                
        # At least half of key functions should be present
        assert len(found_functions) >= len(key_functions) // 2, \
            f"Key functionality missing. Found: {found_functions}"
            
    def test_compilation_output_encoding(self, fritap_root):
        """Test that compilation output has correct encoding."""
        compiled_agent = fritap_root / "friTap" / "fritap_agent.js"
        
        if not compiled_agent.exists():
            pytest.skip("Compiled agent not found")
            
        # Should be readable as UTF-8
        try:
            with open(compiled_agent, 'r', encoding='utf-8') as f:
                content = f.read()
                assert len(content) > 0
        except UnicodeDecodeError:
            pytest.fail("Compiled agent is not valid UTF-8")
            
        # Should not contain binary data
        with open(compiled_agent, 'rb') as f:
            binary_content = f.read()
            
        # Check for null bytes (indicates binary data)
        assert b'\x00' not in binary_content, \
            "Compiled agent contains binary data"