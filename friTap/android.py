#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from os.path import exists as file_exists
from functools import cached_property, wraps
import os
import frida
import subprocess
import shlex
import re
import logging
from .fritap_utility import Success, Failure


class Android:
    tcpdump_arch_map = {
        "arm64": "tcpdump_arm64_android",
        "arm": "tcpdump_arm32_android",
        "ia32": "tcpdump_x86_android",
        "x64": "tcpdump_x86_64_android",
    }
    dst_path = "/data/local/tmp/"
    pcap_name = ""

    def __init__(self, debug_infos=False, device_id=None):
        self.device_id = device_id
        self.print_debug_infos = debug_infos
        self.logger = logging.getLogger('friTap')

    @cached_property
    def adb(self):
        return ADB.find(device_id=self.device_id)

    @cached_property
    def device(self):
        return self.get_frida_device()

    @cached_property
    def tcpdump_version(self):
        arch = self._get_android_device_arch()
        try:
            return self.tcpdump_arch_map[arch]
        except KeyError:
            self.logger.error("unknown arch.")
            self.logger.error("We can't find your device architecture using frida, please set mobile arch via --m_arch <arm64|arm|ia32|x64>")
            self.logger.error("Leaving....")
            raise Failure

    def get_frida_device(self):
        try:
            if self.device_id:
                return frida.get_device_manager().get_device(self.device_id, timeout=5)
            return frida.get_usb_device()
        except frida.InvalidArgumentError:
            self.logger.error(f"Device not found. Please verify the device ID: {self.device_id}")
            raise Failure

    def adb_check_root(self):
        return self.adb.is_rooted

    def _adb_push_file(self, src_file,dst):
        return self.adb.run('push', src_file, dst, timeout=30)
    push_file = _adb_push_file
    
    def _adb_pull_file(self,src_file,dst):
        return self.adb.run('pull', src_file, dst, timeout=30)
    pull_file = _adb_pull_file

    def file_exists(self, path):
        result = self.adb.shell('stat', f'"{path}"')
        return result.returncode == 0

    def _get_android_device_arch(self):
        try:
            frida_usb_json_data = self.device.query_system_parameters()
        except Exception:
            # Defaulting to ARM64
            return "arm64"
        return frida_usb_json_data['arch']
    
    
    def _adb_make_binary_executable(self, path):
        self.adb.shell(f'chmod +x "{path}{self.tcpdump_version}"')

    def debug_print(self, *args, **kwargs):
        """Print debug messages using the logger's debug level."""
        # Join args into a single message string for the logger
        message = ' '.join(str(arg) for arg in args)
        self.logger.debug(message)

    def assure_android(func):
        wraps(func)
        def wrapped(self, *args, **kwargs):
            if not self.is_Android:
                raise Failure(info="[-] none Android device\nclosing friTap...")
            return func(self, *args, **kwargs)
        return wrapped

    @property
    def tcpdump_path(self):
        if self.is_tcpdump_available:
            return "tcpdump"
        return f"{self.dst_path}./{self.tcpdump_version}"

    @property
    def tcpdump_cmd(self):
        return "tcpdump" if self.is_tcpdump_available else self.tcpdump_version
        
    @cached_property
    def is_tcpdump_available(self):
        try:
            # Check if tcpdump is available on the device
            result = self.adb.shell("tcpdump --version")
            return result.returncode == 0
        except Exception as e:
            self.logger.warning(f"Error checking tcpdump availability: {e}")
            return False
            
    
    def _get_tcpdump_version(self):
        # Get the path to the current file
        current_dir = os.path.dirname(__file__)

        # Construct the path to the assets directory
        tcpdump_path = os.path.join(current_dir, 'assets', 'tcpdump_binaries', self.tcpdump_version)

        if file_exists(tcpdump_path):
            self.logger.info(f"installing tcpdump to Android device: {tcpdump_path}")
            return tcpdump_path
        else:
            self.logger.error(f"can't find {tcpdump_path}")
            self.logger.error(f"ensure that {tcpdump_path} exists")
            raise Failure

    @assure_android
    def install_tcpdump(self):
        tcpdump_path = self._get_tcpdump_version()
        return_Value = self._adb_push_file(tcpdump_path,self.dst_path)

        if return_Value.returncode != 0:
            self.logger.error(f"error: {return_Value.stderr}")
            self.logger.error("it might help to adjust the dst_path or to ensure that you have adb in your path")
            raise Failure

        self._adb_make_binary_executable(self.dst_path)
        self.logger.info(f"pushed tcpdump to {self.dst_path} on your android device")
        return True
            
    @assure_android
    def pull_pcap_from_device(self):
        pcap_path = self.dst_path + self.pcap_name
        return_Value = self._adb_pull_file(pcap_path,".")
        self.logger.info(f"pulling capture from device: {return_Value.stdout.strip()}")
        self.debug_print("---------------------------------")
        self.debug_print(return_Value)
        if return_Value.returncode !=0:
            self.logger.error(f"error pulling pcap ({pcap_path}) from android device")

    def get_pid(self, process_name):
        pids = self.get_pids(process_name)
        if len(pids) > 0:
            return pids[0]

    def get_pids(self, process_name):
        try:
            pid_result =self.adb.shell(f'pidof -x "{process_name}"', timeout=10).stdout
            pids = pid_result.strip().split()

            if not pids:
                self.debug_print("[-] No PID found. Process may not be running.")
            return [int(pid) for pid in pids]
        except subprocess.CalledProcessError as e:
            self.debug_print(f"Error: {e.stderr.strip()}")
        except ValueError as e:
            self.debug_print(f"Error: got non-numeric pids? {e}")
        return []
            
    @assure_android
    def send_ctrlC_over_adb(self):
        pids = self.get_pids(self.tcpdump_cmd)
        if pids:
            pids_str = " ".join(map(str, pids))
            self.adb.shell(f"kill -INT {pids_str}")
            self.debug_print(f"[*] Killed processes with PID: {pids_str}")
        else:
            self.debug_print("[-] No running tcpdump processes found")

    @assure_android
    def send_kill_tcpdump_over_adb(self):
        pids = self.get_pids(self.tcpdump_cmd)

        if pids:
            pids_str = " ".join(map(str, pids))
            self.adb.shell(f"kill -9 {pids_str}")
            self.debug_print(f"[*] Killed processes with PID: {pids_str}")
        else:
            self.debug_print("[-] No running tcpdump processes found")
        


    @assure_android
    def run_tcpdump_capture(self,pcap_name):
        self.pcap_name = pcap_name
        tcpdump_cmd = f'{self.tcpdump_path} -U -i any -s 0 -w {self.dst_path}{pcap_name} "not \\(tcp port 5555 or tcp port 27042\\)"'

        # Show the full command that will be executed
        elevator_args = self.adb._elevator(tcpdump_cmd)
        full_cmd = "adb shell " + " ".join(f'"{arg}"' if " " in arg else arg for arg in elevator_args)
        self.debug_print("Running tcpdump in background:", full_cmd)
        return self.adb.shell(tcpdump_cmd, popen=True)

    def start_tcpdump(self, pcap_name):
        return self.run_tcpdump_capture(pcap_name)

    def stop_tcpdump(self, capture_process):
        if capture_process:
            try:
                capture_process.terminate()
                capture_process.wait(timeout=2)
            except Exception as exc:
                self.debug_print("Exception while closing tcpdump:", exc)
                return False
        else:
            self.send_kill_tcpdump_over_adb()
        return True
            

    def check_adb_availability(self):
        try:
            subprocess.run(['adb', 'version'], capture_output=True, text=True, timeout=5)
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.error("can't find adb in your path. Please ensure that adb is installed and in your path if you are trying a full capture on Android.")
            return False

    def list_devices(self):
        lines = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=10).stdout.splitlines()
        return [x.split()[0] for x in lines[1:] if x]

    def list_installed_packages(self):
        lines = self.adb.shell('pm', 'list', 'packages', timeout=15).stdout.splitlines()
        return [self.adb._parse_package_name(x) for x in lines]

    @cached_property
    def is_Android(self):
        if self.check_adb_availability() and len(self.list_devices()) >= 1:
            return True
        else:
            self.logger.error("No device connected to adb. Ensure that adb devices will print your device if you are trying a full capture on Android.")
            return False
        
class ADB:
    def __init__(self, device_id=None):
        self.device_id = device_id
        self.logger = logging.getLogger('friTap')

    def _to_runlist(self, *args):
        if len(args) == 1:
            return shlex.split(args[0]) if isinstance(args[0], str) else args[0]
        return args

    @property
    def is_rooted(self):
        return type(self) is not ADB

    def _elevator(self, cmd):
        # if we reach this, no elevator has been found and we are not rooted.
        self.logger.error("none rooted device. Please root it before trying a full-capture with friTap and ensure that you are able to run commands with the su-binary....")
        raise ValueError

    @property
    def _adb_base(self):
        if self.device_id:
            return ['adb', '-s', self.device_id]
        return ['adb']
        
    def _adb_cmd(self, *args):
        if len(args) == 1 and isinstance(args[0], str):
            return self._adb_base + shlex.split(args[0])
        return self._adb_base + list(args)

    def _parse_package_name(self, name):
        return name.split(":")[1] if  ":" in name else name

    package_re = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
    def _validate_package_name(self, name):
        """
        https://developer.android.com/build/configure-app-module#set-application-id

        Although the application ID looks like a traditional Kotlin or Java
        package name, the naming rules for the application ID are a bit more
        restrictive:

        - It must have at least two segments (one or more dots).
        - Each segment must start with a letter.
        - All characters must be alphanumeric or an underscore [a-zA-Z0-9_].

        """
        # stringifying name makes None to 'None' which is equally invalid thus works
        return bool(self.package_re.match(str(name)))

    def run(self, *args, **kwargs):
        run_kwargs = {"capture_output": True, "text": True, "timeout": 5}
        run_kwargs.update(kwargs)        
        return subprocess.run(self._adb_cmd(*args), **run_kwargs)

    def Popen(self, *args, **kwargs):
        popen_kwargs = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        popen_kwargs.update(kwargs)
        return subprocess.Popen(self._adb_cmd(*args), **popen_kwargs)

    def shell(self, *args, popen=False, **kwargs):
        cmd = ' '.join(args) if len(args) > 1 else args[0]
        shell_args=['shell'] + self._elevator(cmd)
        if popen:
            return self.Popen(*shell_args, **kwargs)
        else:
            return self.run(*shell_args, **kwargs)

    @staticmethod
    def find(device_id=None):
        for adb in ADB.__subclasses__() + [ADB]:
            try:
                return adb.detect(device_id=device_id)
            except (ValueError, subprocess.TimeoutExpired):
                continue
        raise Failure("[-] No ADB: there seems to be no adb and/or connection available")

    @classmethod
    def detect(cls, device_id=None):
        adb = cls(device_id=device_id)
        uid = int(adb.shell('id -u', timeout=1).stdout) # may raise, that's ok
        if (uid == 0) == adb.is_rooted:
            return adb
        raise ValueError

class RootADB(ADB):
    # The Root elevator means: no su; works directly on uid-0 shell
    def _elevator(self, cmd):
        return [cmd]

class SuADB(ADB):
    def _elevator(self, cmd):
        return ['su', '0', cmd]

class MagiskADB(ADB):
    def _elevator(self, cmd):
        return ['su', '-c', cmd]
