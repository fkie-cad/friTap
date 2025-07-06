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
    target="firefox",           # Target application
    pcap_file="traffic.pcap",   # PCAP output file
    verbose=True,               # Enable verbose output
    spawn=False,                # Attach to existing process
    keylog_file="keys.log",     # Key log file
    enable_spawn_gating=False,  # Spawn gating
    mobile=False,               # Mobile mode
    live=False,                 # Live analysis
    environment=None,           # Environment variables
    debug=False,                # Debug mode
    full_capture=False,         # Full packet capture
    socket_tracing=False,       # Socket tracing
    host=None,                  # Remote host
    offsets=None,               # Custom offsets
    debug_output=False,         # Debug output only
    experimental=False,         # Experimental features
    anti_root=False,            # Anti-root bypass
    payload_modification=False, # Payload modification
    enable_default_fd=False,    # Default FD info
    patterns=None,              # Pattern file
    custom_script=None          # Custom Frida script
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
        self.target = None
        self.pcap_file = None
        self.keylog_file = None
        self.verbose = False
        self.mobile = False
        self.patterns = None
        
    def to_dict(self):
        return {
            'target': self.target,
            'pcap_file': self.pcap_file,
            'keylog_file': self.keylog_file,
            'verbose': self.verbose,
            'mobile': self.mobile,
            'patterns': self.patterns
        }

# Usage
config = FriTapConfig()
config.target = "firefox"
config.keylog_file = "keys.log"
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
    
    keylog_file = f"{output_dir}/{package_name}_keys.log"
    pcap_file = f"{output_dir}/{package_name}_traffic.pcap"
    
    logger = SSL_Logger(
        target=package_name,
        pcap_file=pcap_file,
        keylog_file=keylog_file,
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
        'keylog_file': keylog_file,
        'pcap_file': pcap_file,
        'target': package_name
    }

# Usage
result = analyze_android_app("com.instagram.android", "/tmp/analysis")
print(f"Analysis complete: {result}")
```

### Pattern-Based Analysis

```python
from friTap import SSL_Logger
import json

def analyze_with_patterns(target, pattern_file):
    """Analyze application using custom patterns"""
    
    # Load pattern file
    with open(pattern_file, 'r') as f:
        patterns = json.load(f)
    
    logger = SSL_Logger(
        target=target,
        keylog_file="pattern_keys.log",
        pcap_file="pattern_traffic.pcap",
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
        keylog_file = f"{self.output_dir}/{target}_{timestamp}_keys.log"
        pcap_file = f"{self.output_dir}/{target}_{timestamp}_traffic.pcap"
        
        logger = SSL_Logger(
            target=target,
            keylog_file=keylog_file,
            pcap_file=pcap_file,
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
            'target': target,
            'keylog_file': keylog_file,
            'pcap_file': pcap_file,
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
                print(f"Completed {target}: {result['keylog_file']}")
            except Exception as e:
                print(f"Error analyzing {target}: {e}")
        
        return self.results

# Usage
analyzer = BatchAnalyzer("/tmp/batch_analysis")
targets = ["firefox", "curl", "wget"]
results = analyzer.analyze_multiple(targets, duration=180)

for result in results:
    print(f"Target: {result['target']}, Keys: {result['keylog_file']}")
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
        
    def analyze_with_callbacks(self, target):
        """Analyze target with custom callbacks"""
        
        # Note: This is a conceptual example
        # Actual callback integration would require friTap modifications
        logger = SSL_Logger(
            target=target,
            keylog_file="callback_keys.log",
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
    
    def create_logger(self, target, overrides=None):
        """Create SSL_Logger with configuration"""
        
        config = self.config.copy()
        if overrides:
            config.update(overrides)
        
        config['target'] = target
        
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
    target="firefox",
    overrides={"keylog_file": "firefox_keys.log"}
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
    def create_logger(target, **overrides):
        """Create logger with environment configuration"""
        
        config = EnvironmentConfig.from_environment()
        config.update(overrides)
        config['target'] = target
        
        # Remove None values
        config = {k: v for k, v in config.items() if v is not None}
        
        return SSL_Logger(**config)

# Usage with environment variables
# export FRITAP_VERBOSE=true
# export FRITAP_MOBILE=true
# export FRITAP_ANTI_ROOT=true

logger = EnvironmentConfig.create_logger(
    "com.example.app",
    keylog_file="env_keys.log"
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
                target=self.target,
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

def analyze_and_visualize(target, duration=60):
    """Analyze target and create visualizations"""
    
    # Start analysis
    logger = SSL_Logger(
        target=target,
        keylog_file=f"{target}_keys.log",
        pcap_file=f"{target}_traffic.pcap",
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
        with open(f"{target}_keys.log", 'r') as f:
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
        plt.title(f'TLS Sessions for {target}')
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
        
    def analyze_with_retry(self, target, max_retries=3, **config):
        """Analyze target with retry logic"""
        
        for attempt in range(max_retries):
            try:
                logger.info(f"Analysis attempt {attempt + 1} for {target}")
                
                self.logger = SSL_Logger(
                    target=target,
                    **config
                )
                
                self.logger.install_signal_handler()
                self.logger.start_fritap_session()
                
                while self.logger.running:
                    time.sleep(1)
                
                logger.info(f"Analysis completed successfully for {target}")
                return True
                
            except Exception as e:
                logger.error(f"Attempt {attempt + 1} failed: {e}")
                logger.debug(traceback.format_exc())
                
                if attempt < max_retries - 1:
                    logger.info(f"Retrying in 5 seconds...")
                    time.sleep(5)
                else:
                    logger.error(f"All {max_retries} attempts failed for {target}")
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
    keylog_file="robust_keys.log",
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
def fritap_session(target, **config):
    """Context manager for friTap sessions"""
    logger = None
    try:
        logger = SSL_Logger(target=target, **config)
        logger.install_signal_handler()
        yield logger
    finally:
        if logger:
            # Cleanup is handled automatically
            pass

# Usage
with fritap_session("firefox", keylog_file="keys.log") as session:
    session.start_fritap_session()
    # Session automatically cleaned up on exit
```

### 2. Configuration Validation

```python
def validate_config(config):
    """Validate friTap configuration"""
    required_fields = ['target']
    
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field: {field}")
    
    if config.get('mobile') and not config.get('target', '').startswith('com.'):
        raise ValueError("Mobile targets should be package names")
    
    return True

# Usage
config = {
    'target': 'com.example.app',
    'mobile': True,
    'keylog_file': 'keys.log'
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
        
    def analyze(self, target, **config):
        """Analyze with proper logging"""
        
        self.logger.info(f"Starting analysis of {target}")
        self.logger.debug(f"Configuration: {config}")
        
        try:
            ssl_logger = SSL_Logger(target=target, **config)
            ssl_logger.install_signal_handler()
            ssl_logger.start_fritap_session()
            
            while ssl_logger.running:
                time.sleep(1)
                
            self.logger.info(f"Analysis completed for {target}")
            
        except Exception as e:
            self.logger.error(f"Analysis failed for {target}: {e}")
            raise
```

## Next Steps

- **Learn about [CLI usage](cli.md)** for command-line integration
- **Check [CLI Reference](cli.md)** for all available options and their Python equivalents
- **Review [Examples](../examples/index.md)** for practical usage patterns
- **See [Troubleshooting](../troubleshooting/common-issues.md)** for common issues