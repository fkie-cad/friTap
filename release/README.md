# Create release build

In order to create a standalone friTap.pyz script archive we ensure at first that the used frida Javascript is on its latest version

```bash
cd <friTap repo>
frida-compile agent/ssl_log.ts -o _ssl_log.js
```

next we invoke the `createRelease.py` script in order to create a friTap.py standalone version:
```bash
cd <friTap repo>/release
./createRelease.py
```

