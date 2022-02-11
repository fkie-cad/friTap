#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import stat

template_index=30
release_string="./friTap.py"

def main():
	with open('../_ssl_log.js') as js_File:
		frida_js_code = js_File.readlines()

	with open("./friTap_release_template.py", "r") as f:
		contents = f.readlines()

	contents.insert(template_index, frida_js_code)

	with open(release_string, "w") as f:
		for lines in contents:
			f.write("".join(str(line) for line in lines))

	st = os.stat(release_string)
	os.chmod(release_string, st.st_mode | stat.S_IEXEC)


if __name__ == "__main__":
    main()