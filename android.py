#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from distutils.command.sdist import sdist
import frida
import subprocess


 
class Android:
    
    def __init__(self,debug_infos=False, arch=""):
        self.dst_path = "/data/local/tmp/"
        self.device = None
        self.pcap_name = ""
        self.print_debug_infos = debug_infos
        self.do_we_have_an_android_device = False
        if self._is_Android():
            self.tcpdump_version = self._get_appropriate_android_tcpdump_version(arch)

        


    
    def adb_check_root(self):
        return bool(subprocess.run(['adb', 'shell','su -v'], capture_output=True, text=True).stdout)
    
    def run_adb_command_as_root(self,command):
        if self.adb_check_root() == False:
            print("[-] none rooted device. Please root it before using friTap and ensure that you are able to run commands with the su-binary....")
            exit(2)
        output = subprocess.run(['adb', 'shell','su -c '+command], capture_output=True, text=True)
        return output

    def _adb_push_file(self,file,dst):
        output = subprocess.run(['adb', 'push',file,dst], capture_output=True, text=True)
        return output
    
    def _adb_pull_file(self,src_file,dst):
        output = subprocess.run(['adb', 'pull',src_file,dst], capture_output=True, text=True)
        return output
    
    def _get_android_device_arch(self):
        frida_usb_json_data = frida.get_usb_device().query_system_parameters()
        return frida_usb_json_data['arch']
    
    
    def _get_appropriate_android_tcpdump_version(self,passed_arch):
        arch = ""
        if len(passed_arch)  > 2:
            arch = passed_arch
        else:
            arch = self._get_android_device_arch()
        
        tcpdump_version = ""
        if arch == "arm64":
            tcpdump_version = "tcpdump_arm64_android"
        elif arch == "arm":
            tcpdump_version = "tcpdump_arm32_android"
        elif arch == "ia32":
            tcpdump_version = "tcpdump_x86_android"
        elif arch == "x64":
            tcpdump_version = "tcpdump_x86_64_android"
        else:
            print("[-] unknown arch.\n We can't find your device architecture using frida, please set mobile arch via --m_arch <arm64|arm|ia32|x64>\n[-] Leaving....")
            exit(2)
            
        return tcpdump_version
    
    def push_tcpdump_to_device(self):
        self.close_friTap_if_none_android()
        tcpdump_path = "assets/tcpdump_binaries/"+self.tcpdump_version
        return_Value = self._adb_push_file(tcpdump_path,self.dst_path)
        if return_Value.returncode != 0:
            print("[-] error: " +  return_Value.stderr)
            print("[-] it might help to adjust the dst_path or to ensure that you have adb in your path")
        else:
            print(f"[*] pushed tcpdump to {self.dst_path} on your android device")
            
    def pull_pcap_from_device(self):
        self.close_friTap_if_none_android()
        pcap_path = self.dst_path + self.pcap_name
        return_Value = self._adb_pull_file(pcap_path,".")
        print("[*] pulling capture from device")
        if self.print_debug_infos:
            print(return_Value)
        if return_Value.returncode !=0:
            print(f"[-] error pulling pcap ({pcap_path}) from android device")
            
    def send_ctrlC_over_adb(self):
        self.close_friTap_if_none_android()
        self.run_adb_command_as_root(f"kill -INT $(pidof -s {self.tcpdump_version})")
        
        
    def close_friTap_if_none_android(self):
        if self.is_Android == False:
            print("[-] none android device\nclosing friTap...")
            exit(2)
    
    def run_tcpdump_capture(self,pcap_name):
        self.close_friTap_if_none_android()
        self.pcap_name = pcap_name
        return subprocess.Popen(['adb', 'shell','su -c '+self.dst_path+'./'+self.tcpdump_version+' -i any -s 0 -w '+self.dst_path+pcap_name])
    
    def _is_Android(self):
        try:
            subprocess.run(['adb'], capture_output=True, text=True)
        except FileNotFoundError:
            print("[-] can't find adb in your path. Please ensure that adb is installed and in your path if you are trying a full capture on Android.")
            return False
        
        if len(subprocess.run(['adb', 'devices'], capture_output=True, text=True).stdout) > 27:
            self.do_we_have_an_android_device = True
            return True
        else:
            print("[-] No device connected to adb. Ensure that adb devices will print your device if you are trying a full capture on Android.")
            return False
        
    def is_Android(self):
        return self.do_we_have_an_android_device
