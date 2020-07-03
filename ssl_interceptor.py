import frida
import argparse
import signal


__author__ = "Max Ufer"
__version__ = "0.01"


def ssl_log(app):
    device = frida.get_usb_device()
    process = device.attach(app)
    with open("_ssl_log.js") as f:
        script = process.create_script(f.read())
    script.on("message", on_message)
    print('[*] Running Script')
    script.load()
    print("Press Ctrl+C to stop logging.")
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass

    process.detach()


def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print("ssl_logger v" + __version__)
        print("by " + __author__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)


if __name__ == "__main__":
    parser = ArgParser(add_help=False, description="Decrypt and log SSL traffic of an android application",
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    args = parser.add_argument_group("Arguments")
    args.add_argument("app", metavar="<application>",
                      help="The full name of the application whose SSL calls to log")
    parsed = parser.parse_args()
    ssl_log(parsed.app)
