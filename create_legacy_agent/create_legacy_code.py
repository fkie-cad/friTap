#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import subprocess
import os
import fileinput
import sys
import shutil

__version__ = "1.0.0"
agent_folder_path = "../agent"

def create_backup_dir():
	shutil.copytree(agent_folder_path, 'agent_backup', dirs_exist_ok=True)

def undo_replacements():
	shutil.rmtree(agent_folder_path)
	shutil.copytree('agent_backup', agent_folder_path, dirs_exist_ok=True)
	shutil.rmtree("agent_backup")
	shutil.rmtree("node_modules")
	

def replace_file_inplace(ts_file,search_expression,replace_expression):
	for line in fileinput.input(ts_file, inplace=1):
		import_statement = "import "
		if search_expression in line and line.startswith(import_statement):
			line = line.replace(search_expression,replace_expression)
		sys.stdout.write(line)

def remove_js_extension(agent_folder, verbose):
	replace_pattern_on_files(agent_folder,".js\";","\";",verbose,True)
	replace_pattern_on_files(agent_folder,".js\"","\";",verbose,True)


def replace_pattern_on_files(agent_folder, search_expression, replace_expression, verbose, is_removing_js_extension):
	for root, dirs, files in os.walk(agent_folder):
		for i in files:
			file_path = os.path.join(root, i)
			if verbose:
				if is_removing_js_extension:
					print(f"Removing .js extension from import_statements in {file_path}")
				else:
					print(f"Adding .js extension to import_statements in  {file_path}")

			replace_file_inplace(file_path,search_expression,replace_expression)


def invoke_frida_compile():
	output = subprocess.run(['npm', 'install','.'], capture_output=True, text=True)


def create_legacy_agent_code(agent_folder,verbose):
	create_backup_dir()
	remove_js_extension(agent_folder_path,verbose)
	invoke_frida_compile()
	undo_replacements()
	#add_js_extension(agent_folder_path,verbose)


def add_js_extension(agent_folder, verbose):
	replace_pattern_on_files(agent_folder,"\";",".js\";",verbose,False)

class ArgParser(argparse.ArgumentParser):
    def error(self, message):
        print("friTap legacy script generator v" + __version__)
        print()
        print("Error: " + message)
        print()
        print(self.format_help().replace("usage:", "Usage:"))
        self.exit(0)

def main():
	parser = ArgParser(
        add_help=False,
        description="Modify the agent code into legacy mode, creates the legacy agent code and undo the changes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples:
  %(prog)s -r
  %(prog)s -a
""")

	args = parser.add_argument_group("Arguments")
	args.add_argument("-r", "--remove", required=False, action="store_const",
                      const=True, default=False, help="Do only removing js extension from the import_statement")
	args.add_argument("-a", "--add", required=False, action="store_const", const=True,
                      help="Do only adding the removed .js extension to the import_statement")
	args.add_argument("-v", "--verbose", required=False, action="store_const", const=True, default=False,
                      help="Do the replacements verbose")

	parsed = parser.parse_args()

	if parsed.remove:
		remove_js_extension(agent_folder_path,parsed.verbose)
	elif parsed.add:
		add_js_extension(agent_folder_path,parsed.verbose)
	else:
		create_legacy_agent_code(agent_folder_path,parsed.verbose)


if __name__ == "__main__":
    main()