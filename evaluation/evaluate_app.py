import argparse
import os
import frida
import subprocess
import sys
import time


def get_files_recursive(path):
    obbs = list()
    for root, dirs, files in os.walk(path):
        for name in files:
            obbs.append(os.path.join(root, name))
    return obbs


def install_apk(apk_path):
    package_name = apk_path.split(os.path.sep)[-1][:-4]
    result = subprocess.run(
        [r"adb", "install", "-g", apk_path], stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        return package_name
    else:
        return None


def install_xapk(apk_path):
    files = os.listdir(apk_path)
    main_apk = [f for f in files if not (f.startswith(
        "config.") or f.startswith("bloops_dynamic") or f.startswith("rate.")) and f.endswith(".apk")]
    if len(main_apk) != 1:
        raise RuntimeError(
            f"Unusual number of main apks in {apk_path}: {','.join(main_apk)}")
    package_name = main_apk[0].split(os.path.sep)[-1][:-4]
    apks = [os.path.join(apk_path, f) for f in files if f.endswith(".apk")]
    obbs = list()
    if "Android" in files:
        obbs = [f for f in get_files_recursive(os.path.join(
            apk_path, "Android", "obb")) if f.endswith(".obb")]
    for obb in obbs:
        subprocess.run(
            ["adb", "push", obb, "/data/media/0/Android/obb"], stdout=subprocess.DEVNULL)
    result = subprocess.run(
        [r"adb", "install-multiple", "-g", *apks], stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        return package_name
    else:
        return None


def install(apk_path):
    if os.path.isfile(apk_path):
        return install_apk(apk_path)
    else:
        return install_xapk(apk_path)


def evaluate(apk_path, verbose):
    def log(message):
        if verbose:
            print(message)

    log(f"[~] Installing {apk_path}...")
    package_name = install(apk_path)
    if not package_name:
        log("[~] Install failed!")
        sys.exit(1)

    log("[~] Spawning app with frida")
    device = frida.get_usb_device()
    pid = device.spawn(package_name)
    time.sleep(2)
    log("[~] Attaching speartrace")
    p_spear = subprocess.Popen(["python3", "speartrace.py",
                                f"-p", package_name, "-o", "/Users/maxufer/Arbeit/sslinterceptor/evaluation/.evaluate_enc.pcap"], cwd="/Users/maxufer/Arbeit/utilities/speartrace", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    log("[~] Attaching interceptor")
    p_interceptor = subprocess.Popen(["python3", "ssl_interceptor.py", package_name,
                                      "-a", "-p", "/Users/maxufer/Arbeit/sslinterceptor/evaluation/.evaluate_dec.pcap", "--enable_spawn_gating"], cwd="/Users/maxufer/Arbeit/sslinterceptor", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    device.resume(pid)
    time.sleep(5)
    log("[~] Starting monkey")
    result = subprocess.run(
        ["adb", "shell", "monkey", "-p", package_name, "500"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(5)
    if result.returncode != 0:
        log("[~] Monkey returned with status 1 (Error)")
    else:
        log("[~] Finished")
    log("[~] Terminating processes")
    p_interceptor.terminate()
    p_spear.terminate()
    log("[~] Uninstalling app")
    subprocess.run(["adb", "uninstall", package_name],
                   stdout=subprocess.DEVNULL)
    subprocess.run(
        ["adb", "shell", 'su -c "rm /data/media/0/Android/obb/*.obb"'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Try ssl_interceptor on app")
    parser.add_argument("app", metavar="<path to apk>")
    parser.add_argument("-v", "--verbose", required=False,
                        action="store_const", const=True)
    parsed = parser.parse_args()
    evaluate(parsed.app, parsed.verbose)
