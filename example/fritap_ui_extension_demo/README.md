# fritap-ui-extension-demo

A small friTap viewer extension (embedding mode C). It registers, through the
`fritap.ui_extensions` entry-point group:

- a **Demo** detail tab with a short summary of the flow (hidden for flows
  without request or response data)
- a **Bytes** flow-list column (total bytes of the flow)
- a **Length summary** body decoder (byte count, printable ratio, hex head),
  listed in the body-processing modal
- the display-filter field `demo.tls_version`, read from the `tls` layer
- a `demo-large-body` analyzer (INFO finding for bodies of 1 MiB or more)

## Install

```bash
pip install -e example/fritap_ui_extension_demo
```

Then open any capture, for example `fritap -r capture.tap` or
`python example/tap_viewer_launch.py capture.tap`. The extension is found by
`friTap.ui.load_extensions()`, which the viewer calls itself (UI extensions only). Set
`FRITAP_DISABLE_UI_EXTENSIONS=1` to turn UI extensions off.

Try the filter `demo.tls_version == "TLSv1.3"` (the value depends on what the
capture stored in the flow's `tls` layer).
