#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import stat
import shutil
import zipapp

template_index=29
fritap_main_entry="./__main__.py"
tmp_folder_name="release_tmp/"
release_string="friTap.pyz"

def create_tmp_release_folder():
	os.mkdir(tmp_folder_name)
	shutil.copy("../friTap/android.py", tmp_folder_name)
	shutil.copy("../friTap/pcap.py", tmp_folder_name)
	shutil.copy("../friTap/__init__.py", tmp_folder_name)
	shutil.copy("__main__.py", tmp_folder_name)


def cleanup():
	try:
		shutil.rmtree(tmp_folder_name)
		os.remove(fritap_main_entry)
	except OSError as e:
		print("Error: %s - %s." % (e.filename, e.strerror))

def create_executable_archive():
	zipapp.create_archive(tmp_folder_name,target=release_string,interpreter="/usr/bin/env python3")

def main():
	with open('../friTap/_ssl_log.js') as js_File:
		frida_js_code = js_File.readlines()

	with open("./friTap_release_template.py", "r") as f:
		contents = f.readlines()

	contents.insert(template_index, frida_js_code)

	with open(fritap_main_entry, "w") as f:
		for lines in contents:
			f.write("".join(str(line) for line in lines))

	st = os.stat(fritap_main_entry)
	os.chmod(fritap_main_entry, st.st_mode | stat.S_IEXEC)
	create_tmp_release_folder()
	create_executable_archive()
	cleanup()


if __name__ == "__main__":
    main()