# Python API

friTap can be used as a Python library for programmatic SSL/TLS traffic analysis and integration into larger security analysis workflows.

## Installation for Python Use

```bash
# Install friTap
pip install fritap

# Import in Python
from friTap import SSL_Logger
```

## Basic Python Usage

### Simple SSL Logger

```python
from friTap import SSL_Logger
import time

# Create SSL logger instance
logger = SSL_Logger(
    app="firefox",              # Target application (process name, PID, or package name)
    pcap_name="traffic.pcap",   # PCAP output file path
    verbose=True,               # Enable verbose output
    spawn=False,                # Attach to existing process (True = spawn new process)
    keylog="keys.log",          # Key log file path (or False to disable)
    enable_spawn_gating=False,  # Intercept spawned child processes
    spawn_gating_all=False,     # Catch ALL spawned processes (use with caution)
    enable_child_gating=False,  # Intercept child processes
    mobile=False,               # Mobile mode (True or device ID string)
    live=False,                 # Live Wireshark analysis via named pipe
    environment_file=None,      # JSON file with environment variables
    debug_mode=False,           # Enable debug mode with Chrome Inspector
    full_capture=False,         # Full packet capture (requires tcpdump)
    socket_trace=False,         # Enable socket tracing
    host=False,                 # Remote Frida host (IP:port string or False)
    offsets=None,               # Custom function offsets (JSON file path)
    debug_output=False,         # Enable debug output only (no Chrome Inspector)
    experimental=False,         # Enable experimental features (e.g., Wine support)
    anti_root=False,            # Enable anti-root detection bypass (Android)
    payload_modification=False, # Enable payload modification capabilities
    enable_default_fd=False,    # Use default socket info when FD lookup fails
    patterns=None,              # Pattern file path for symbol-less hooking
    custom_hook_script=None,    # Custom Frida script to load before friTap hooks
    json_output=None,           # JSON output file for session metadata
    install_lsass_hook=True,    # Hook LSASS for Schannel key extraction (Windows)
    timeout=None                # Timeout in seconds for process suspension
)

# Install signal handler for cleanup
logger.install_signal_handler()

# Start analysis session
logger.start_fritap_session()

# Keep running
try:
    while logger.running:
        time.sleep(1)
except KeyboardInterrupt:
    print("Stopping analysis...")
finally:
    # Cleanup is handled automatically
    pass
```

### Configuration Class

```python
from friTap import SSL_Logger

class FriTapConfig:
    def __init__(self):
        self.app = None
        self.pcap_name = None
        self.keylog = None
        self.verbose = False
        self.mobile = False
        self.patterns = None

    def to_dict(self):
        return {
            'app': self.app,
            'pcap_name': self.pcap_name,
            'keylog': self.keylog,
            'verbose': self.verbose,
            'mobile': self.mobile,
            'patterns': self.patterns
        }

# Usage
config = FriTapConfig()
config.app = "firefox"
config.keylog = "keys.log"
config.verbose = True

logger = SSL_Logger(**config.to_dict())
```

## Advanced Usage Examples

### Mobile Application Analysis

```python
from friTap import SSL_Logger
import json

def analyze_android_app(package_name, output_dir):
    """Analyze Android application SSL traffic"""

    keylog_path = f"{output_dir}/{package_name}_keys.log"
    pcap_path = f"{output_dir}/{package_name}_traffic.pcap"

    logger = SSL_Logger(
        app=package_name,
        pcap_name=pcap_path,
        keylog=keylog_path,
        verbose=True,
        mobile=True,                    # Enable mobile mode
        spawn=True,                     # Spawn application
        enable_spawn_gating=True,       # Capture child processes
        anti_root=True,                 # Bypass root detection
        enable_default_fd=True          # Fallback socket info
    )

    logger.install_signal_handler()
    logger.start_fritap_session()

    # Wait for analysis completion
    while logger.running:
        time.sleep(1)

    return {
        'keylog': keylog_path,
        'pcap': pcap_path,
        'app': package_name
    }

# Usage
result = analyze_android_app("com.instagram.android", "/tmp/analysis")
print(f"Analysis complete: {result}")
```

### Pattern-Based Analysis

```python
from friTap import SSL_Logger
import json

def analyze_with_patterns(target_app, pattern_file):
    """Analyze application using custom patterns"""

    # Load pattern file to verify format
    with open(pattern_file, 'r') as f:
        patterns_data = json.load(f)

    logger = SSL_Logger(
        app=target_app,
        keylog="pattern_keys.log",
        pcap_name="pattern_traffic.pcap",
        verbose=True,
        patterns=pattern_file,          # Use pattern file
        debug_output=True               # Enable debug output
    )

    logger.install_signal_handler()
    logger.start_fritap_session()

    while logger.running:
        time.sleep(1)

# Usage for Flutter app
analyze_with_patterns("com.flutter.app", "flutter_patterns.json")
```

### Batch Analysis

```python
from friTap import SSL_Logger
import time
import threading
from datetime import datetime

class BatchAnalyzer:
    def __init__(self, output_dir="./analysis"):
        self.output_dir = output_dir
        self.results = []
        
    def analyze_target(self, target, duration=300):
        """Analyze single target for specified duration"""

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        keylog_path = f"{self.output_dir}/{target}_{timestamp}_keys.log"
        pcap_path = f"{self.output_dir}/{target}_{timestamp}_traffic.pcap"

        logger = SSL_Logger(
            app=target,
            keylog=keylog_path,
            pcap_name=pcap_path,
            verbose=False,              # Reduce output for batch
            timeout=duration
        )

        logger.install_signal_handler()
        logger.start_fritap_session()

        # Wait for completion or timeout
        start_time = time.time()
        while logger.running and (time.time() - start_time) < duration:
            time.sleep(1)

        result = {
            'app': target,
            'keylog': keylog_path,
            'pcap': pcap_path,
            'duration': time.time() - start_time,
            'timestamp': timestamp
        }

        self.results.append(result)
        return result
    
    def analyze_multiple(self, targets, duration=300):
        """Analyze multiple targets sequentially"""
        
        for target in targets:
            print(f"Starting analysis of {target}")
            try:
                result = self.analyze_target(target, duration)
                print(f"Completed {target}: {result['keylog']}")
            except Exception as e:
                print(f"Error analyzing {target}: {e}")
        
        return self.results

# Usage
analyzer = BatchAnalyzer("/tmp/batch_analysis")
targets = ["firefox", "curl", "wget"]
results = analyzer.analyze_multiple(targets, duration=180)

for result in results:
    print(f"App: {result['app']}, Keys: {result['keylog']}")
```

### Custom Callback Integration

```python
from friTap import SSL_Logger
import json

class CustomAnalyzer:
    def __init__(self):
        self.session_count = 0
        self.data_transferred = 0
        
    def on_session_start(self, session_info):
        """Called when new TLS session starts"""
        self.session_count += 1
        print(f"New session #{self.session_count}: {session_info}")
        
    def on_data_captured(self, data_info):
        """Called when data is captured"""
        self.data_transferred += data_info.get('size', 0)
        print(f"Data captured: {data_info['size']} bytes")
        
    def analyze_with_callbacks(self, target_app):
        """Analyze target with custom callbacks"""

        # Note: This is a conceptual example
        # Actual callback integration would require friTap modifications
        logger = SSL_Logger(
            app=target_app,
            keylog="callback_keys.log",
            verbose=True
        )
        
        # Custom callback attachment would go here
        # logger.on_session_start = self.on_session_start
        # logger.on_data_captured = self.on_data_captured
        
        logger.install_signal_handler()
        logger.start_fritap_session()
        
        while logger.running:
            time.sleep(1)
        
        return {
            'sessions': self.session_count,
            'data_transferred': self.data_transferred
        }

# Usage
analyzer = CustomAnalyzer()
stats = analyzer.analyze_with_callbacks("firefox")
print(f"Analysis complete: {stats}")
```

## Configuration Management

### Configuration File Support

```python
import json
from friTap import SSL_Logger

class FriTapConfigManager:
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file) if config_file else {}
        
    def load_config(self, config_file):
        """Load configuration from JSON file"""
        with open(config_file, 'r') as f:
            return json.load(f)
    
    def save_config(self, config_file):
        """Save configuration to JSON file"""
        with open(config_file, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def create_logger(self, target_app, overrides=None):
        """Create SSL_Logger with configuration"""

        config = self.config.copy()
        if overrides:
            config.update(overrides)

        config['app'] = target_app

        return SSL_Logger(**config)

# Example configuration file (config.json)
config_data = {
    "verbose": True,
    "mobile": False,
    "enable_spawn_gating": False,
    "anti_root": False,
    "debug_output": False
}

# Save configuration
with open("config.json", "w") as f:
    json.dump(config_data, f, indent=2)

# Usage
config_manager = FriTapConfigManager("config.json")
logger = config_manager.create_logger(
    target_app="firefox",
    overrides={"keylog": "firefox_keys.log"}
)
```

### Environment-Based Configuration

```python
import os
from friTap import SSL_Logger

class EnvironmentConfig:
    @staticmethod
    def from_environment():
        """Create configuration from environment variables"""
        
        return {
            'verbose': os.getenv('FRITAP_VERBOSE', 'false').lower() == 'true',
            'mobile': os.getenv('FRITAP_MOBILE', 'false').lower() == 'true',
            'debug_output': os.getenv('FRITAP_DEBUG', 'false').lower() == 'true',
            'anti_root': os.getenv('FRITAP_ANTI_ROOT', 'false').lower() == 'true',
            'timeout': int(os.getenv('FRITAP_TIMEOUT', '300')),
            'patterns': os.getenv('FRITAP_PATTERNS'),
            'host': os.getenv('FRITAP_HOST')
        }
    
    @staticmethod
    def create_logger(target_app, **overrides):
        """Create logger with environment configuration"""

        config = EnvironmentConfig.from_environment()
        config.update(overrides)
        config['app'] = target_app

        # Remove None values
        config = {k: v for k, v in config.items() if v is not None}

        return SSL_Logger(**config)

# Usage with environment variables
# export FRITAP_VERBOSE=true
# export FRITAP_MOBILE=true
# export FRITAP_ANTI_ROOT=true

logger = EnvironmentConfig.create_logger(
    "com.example.app",
    keylog="env_keys.log"
)
```

## Integration Examples

### Flask Web Service

```python
from flask import Flask, request, jsonify
from friTap import SSL_Logger
import threading
import time
import uuid

app = Flask(__name__)
active_sessions = {}

class AnalysisSession:
    def __init__(self, session_id, target, config):
        self.session_id = session_id
        self.target = target
        self.config = config
        self.logger = None
        self.thread = None
        self.status = "initialized"
        
    def start(self):
        """Start analysis in background thread"""
        self.thread = threading.Thread(target=self._run_analysis)
        self.thread.start()
        self.status = "running"
        
    def _run_analysis(self):
        """Run analysis in thread"""
        try:
            self.logger = SSL_Logger(
                app=self.target,
                **self.config
            )
            self.logger.install_signal_handler()
            self.logger.start_fritap_session()
            
            while self.logger.running:
                time.sleep(1)
                
            self.status = "completed"
        except Exception as e:
            self.status = f"error: {e}"

@app.route('/analyze', methods=['POST'])
def start_analysis():
    """Start new analysis session"""
    data = request.json
    
    session_id = str(uuid.uuid4())
    target = data.get('target')
    config = data.get('config', {})
    
    session = AnalysisSession(session_id, target, config)
    session.start()
    
    active_sessions[session_id] = session
    
    return jsonify({
        'session_id': session_id,
        'status': 'started',
        'target': target
    })

@app.route('/status/<session_id>')
def get_status(session_id):
    """Get analysis session status"""
    session = active_sessions.get(session_id)
    
    if not session:
        return jsonify({'error': 'Session not found'}), 404
    
    return jsonify({
        'session_id': session_id,
        'target': session.target,
        'status': session.status
    })

if __name__ == '__main__':
    app.run(debug=True)
```

### Jupyter Notebook Integration

```python
# Jupyter notebook cell
from friTap import SSL_Logger
import matplotlib.pyplot as plt
import pandas as pd
import time

def analyze_and_visualize(target_app, duration=60):
    """Analyze target and create visualizations"""

    # Start analysis
    logger = SSL_Logger(
        app=target_app,
        keylog=f"{target_app}_keys.log",
        pcap_name=f"{target_app}_traffic.pcap",
        verbose=True
    )
    
    logger.install_signal_handler()
    logger.start_fritap_session()
    
    # Monitor for specified duration
    start_time = time.time()
    while logger.running and (time.time() - start_time) < duration:
        time.sleep(1)
    
    # Process results (this would require additional parsing)
    # This is a conceptual example
    
    # Read key log file
    keys_data = []
    try:
        with open(f"{target_app}_keys.log", 'r') as f:
            for line in f:
                if line.startswith('CLIENT_RANDOM'):
                    keys_data.append({
                        'timestamp': time.time(),  # Would need actual timestamp
                        'type': 'CLIENT_RANDOM'
                    })
    except FileNotFoundError:
        pass
    
    # Create DataFrame
    df = pd.DataFrame(keys_data)
    
    # Plot results
    if not df.empty:
        plt.figure(figsize=(10, 6))
        plt.plot(df['timestamp'], range(len(df)))
        plt.title(f'TLS Sessions for {target_app}')
        plt.xlabel('Time')
        plt.ylabel('Session Count')
        plt.show()
    
    return df

# Usage in Jupyter
# result_df = analyze_and_visualize("firefox", duration=120)
# print(f"Captured {len(result_df)} TLS sessions")
```

## Error Handling

### Robust Error Handling

```python
from friTap import SSL_Logger
import logging
import traceback

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RobustAnalyzer:
    def __init__(self):
        self.logger = None
        
    def analyze_with_retry(self, target_app, max_retries=3, **config):
        """Analyze target with retry logic"""

        for attempt in range(max_retries):
            try:
                logger.info(f"Analysis attempt {attempt + 1} for {target_app}")

                self.logger = SSL_Logger(
                    app=target_app,
                    **config
                )
                
                self.logger.install_signal_handler()
                self.logger.start_fritap_session()
                
                while self.logger.running:
                    time.sleep(1)
                
                logger.info(f"Analysis completed successfully for {target_app}")
                return True

            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed: {e}")
                logger.debug(traceback.format_exc())

                if attempt < max_retries - 1:
                    logger.info(f"Retrying in 5 seconds...")
                    time.sleep(5)
                else:
                    logger.error(f"All {max_retries} attempts failed for {target_app}")
                    return False
        
        return False
    
    def cleanup(self):
        """Cleanup resources"""
        if self.logger:
            # Cleanup would be handled by SSL_Logger
            pass

# Usage
analyzer = RobustAnalyzer()
success = analyzer.analyze_with_retry(
    "firefox",
    max_retries=3,
    keylog="robust_keys.log",
    verbose=True
)

if success:
    print("Analysis completed successfully")
else:
    print("Analysis failed after retries")
```

## Best Practices

### 1. Resource Management

```python
from contextlib import contextmanager
from friTap import SSL_Logger

@contextmanager
def fritap_session(target_app, **config):
    """Context manager for friTap sessions"""
    ssl_logger = None
    try:
        ssl_logger = SSL_Logger(app=target_app, **config)
        ssl_logger.install_signal_handler()
        yield ssl_logger
    finally:
        if ssl_logger:
            # Cleanup is handled automatically
            pass

# Usage
with fritap_session("firefox", keylog="keys.log") as session:
    session.start_fritap_session()
    # Session automatically cleaned up on exit
```

### 2. Configuration Validation

```python
def validate_config(config):
    """Validate friTap configuration"""
    required_fields = ['app']

    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field: {field}")

    if config.get('mobile') and not config.get('app', '').startswith('com.'):
        raise ValueError("Mobile targets should be package names")

    return True

# Usage
config = {
    'app': 'com.example.app',
    'mobile': True,
    'keylog': 'keys.log'
}

if validate_config(config):
    logger = SSL_Logger(**config)
```

### 3. Logging Integration

```python
import logging
from friTap import SSL_Logger

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class LoggingAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def analyze(self, target_app, **config):
        """Analyze with proper logging"""

        self.logger.info(f"Starting analysis of {target_app}")
        self.logger.debug(f"Configuration: {config}")

        try:
            ssl_logger = SSL_Logger(app=target_app, **config)
            ssl_logger.install_signal_handler()
            ssl_logger.start_fritap_session()

            while ssl_logger.running:
                time.sleep(1)

            self.logger.info(f"Analysis completed for {target_app}")

        except Exception as e:
            self.logger.error(f"Analysis failed for {target_app}: {e}")
            raise
```

## Next Steps

- **Learn about [CLI usage](cli.md)** for command-line integration
- **Check [CLI Reference](cli.md)** for all available options and their Python equivalents
- **Review [Examples](../examples/index.md)** for practical usage patterns
- **See [Troubleshooting](../troubleshooting/common-issues.md)** for common issues