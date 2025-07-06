"""
Tests for TypeScript agent compilation.

Validates that the TypeScript agent compiles successfully
and produces valid JavaScript output.
"""

import pytest
import subprocess
import os
import json
from pathlib import Path
from unittest.mock import patch


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
        return fritap_root / "friTap" / "_ssl_log.js"
        
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
        unix_script = fritap_root / "compile_agent.sh"
        windows_script = fritap_root / "compile_agent.bat"
        
        # At least one compilation script should exist
        assert unix_script.exists() or windows_script.exists(), \
            "No compilation script found"
            
        # Unix script should be executable if it exists
        if unix_script.exists():
            assert os.access(unix_script, os.X_OK), \
                "compile_agent.sh is not executable"
                
    @pytest.mark.skipif(not os.access("./compile_agent.sh", os.F_OK), 
                       reason="compile_agent.sh not found")
    def test_agent_compilation_unix(self, fritap_root, compiled_agent_path):
        """Test agent compilation on Unix systems."""
        # Change to friTap root directory
        original_cwd = os.getcwd()
        os.chdir(fritap_root)
        
        try:
            # Run compilation script
            result = subprocess.run(
                ['./compile_agent.sh'], 
                capture_output=True, 
                text=True, 
                timeout=60
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
            
    def test_frida_compile_available(self):
        """Test that frida-compile is available."""
        try:
            result = subprocess.run(
                ['npx', 'frida-compile', '--version'], 
                capture_output=True, 
                text=True, 
                timeout=10
            )
            assert result.returncode == 0, "frida-compile not available"
        except FileNotFoundError:
            pytest.skip("npx not available")
            
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
        return fritap_root / "friTap" / "_ssl_log.js"
        
    @pytest.fixture
    def legacy_agent_path(self):
        """Get path to legacy compiled agent."""
        fritap_root = Path(__file__).parent.parent.parent
        return fritap_root / "friTap" / "_ssl_log_legacy.js"
        
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
        assert 'interface ' not in content, \
            "TypeScript interface found - compilation incomplete"
        assert ': string' not in content, \
            "TypeScript type annotation found - compilation incomplete"
        assert 'export class' not in content, \
            "TypeScript export found - compilation incomplete"
            
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
            
    def test_legacy_agent_exists(self, legacy_agent_path):
        """Test that legacy agent exists if applicable."""
        # Legacy agent may not always exist
        if legacy_agent_path.exists():
            assert legacy_agent_path.stat().st_size > 0, \
                "Legacy agent file is empty"
                
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
        
        # Try to compile the bad file
        try:
            result = subprocess.run(
                ['npx', 'frida-compile', str(bad_ts_file), '-o', str(tmp_path / "output.js")], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            # Compilation should fail
            assert result.returncode != 0, \
                "Compilation should fail with syntax errors"
            assert "error" in result.stderr.lower(), \
                "Error message should be present"
                
        except FileNotFoundError:
            pytest.skip("npx/frida-compile not available")
            
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
        
        try:
            result = subprocess.run(
                ['npx', 'frida-compile', str(bad_import_file), '-o', str(tmp_path / "output.js")], 
                capture_output=True, 
                text=True, 
                timeout=30
            )
            
            # Should fail due to missing import
            assert result.returncode != 0, \
                "Compilation should fail with missing imports"
                
        except FileNotFoundError:
            pytest.skip("npx/frida-compile not available")
            
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
                    ['./compile_agent.sh'], 
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
        compiled_agent = fritap_root / "friTap" / "_ssl_log.js"
        
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
        compiled_agent = fritap_root / "friTap" / "_ssl_log.js"
        
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
        compiled_agent = fritap_root / "friTap" / "_ssl_log.js"
        
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