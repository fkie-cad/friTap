import argparse
import os
import frida
import subprocess
import sys
import time
import adb_random_input
from pcap_compare import compare

ENC_PATH = "/home/he1n/sslinterceptor/evaluation/.evaluate_enc.pcap"
DEC_PATH = "/home/he1n/sslinterceptor/evaluation/.evaluate_dec.pcap"


def get_files_recursive(path):
    obbs = list()
    for root, dirs, files in os.walk(path):
        for name in files:
            obbs.append(os.path.join(root, name))
    return obbs


def __install_apk(apk_path):
    package_name = apk_path.split(os.path.sep)[-1][:-4]
    result = subprocess.run(
        [r"adb", "install", "-g", apk_path], stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        return package_name
    else:
        return None


def __install_xapk(apk_path):
    files = os.listdir(apk_path)
    main_apk = [f for f in files if not (f.startswith(
        "config.") or f.startswith("bloops_dynamic") or f.startswith("rate.")) and f.endswith(".apk")]
    if len(main_apk) != 1:
        raise RuntimeError(
            f"{apk_path}: Unusual number of main apks: {','.join(main_apk)}")
    package_name = main_apk[0].split(os.path.sep)[-1][:-4]
    apks = [os.path.join(apk_path, f) for f in files if f.endswith(".apk")]
    obbs = list()
    if "Android" in files:
        obbs = [f for f in get_files_recursive(os.path.join(
            apk_path, "Android", "obb")) if f.endswith(".obb")]
    for obb in obbs:
        subprocess.run(
            ["adb", "push", obb, "/data/local/tmp"], stdout=subprocess.DEVNULL)
        obb_without_path = obb.split("/")[-1]
        subprocess.run(
            ["adb", "shell", "su", "-c", "mv", f"/data/local/tmp/{obb_without_path}", "/data/media/0/Android/obb"], stdout=subprocess.DEVNULL)
    result = subprocess.run(
        [r"adb", "install-multiple", "-g", *apks], stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        return package_name
    else:
        return None


def install_apk(apk_path):
    if os.path.isfile(apk_path):
        return __install_apk(apk_path)
    else:
        return __install_xapk(apk_path)


def evaluate(app, verbose, keep_files, monkey_delay, install, manual, enable_spawn_gating, custom_input):
    def log(message):
        if verbose:
            print(message)
    if install:
        log(f"[~] Installing {app}...")
        try:
            package_name = install_apk(app)
        except Exception as e:
            sys.stderr.write(f"{app}: Install failed")
            sys.exit()
        if not package_name:
            sys.stderr.write(f"{app}: Install failed")
            sys.exit(1)
    else:
        package_name = app

    log("[~] Spawning app with frida")
    device = frida.get_usb_device()
    pid = device.spawn(package_name)
    time.sleep(2)
    log("[~] Attaching speartrace")
    if enable_spawn_gating:
        p_spear = subprocess.Popen(["python3", "speartrace.py",
                                    f"-p", package_name, "-o", ENC_PATH, "--enable_spawn_gating"], cwd="/home/he1n/sslinterceptor/evaluation/speartrace", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        p_spear = subprocess.Popen(["python3", "speartrace.py",
                                    f"-p", package_name, "-o", ENC_PATH], cwd="/home/he1n/sslinterceptor/evaluation/speartrace", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    log("[~] Attaching interceptor")
    if enable_spawn_gating:
        p_interceptor = subprocess.Popen(["python3", "ssl_interceptor.py", package_name,
                                          "-a", "-p", DEC_PATH, "--enable_spawn_gating"], cwd="/home/he1n/sslinterceptor", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        p_interceptor = subprocess.Popen(["python3", "ssl_interceptor.py", package_name,
                                          "-a", "-p", DEC_PATH], cwd="/home/he1n/sslinterceptor", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    log(f"[~] Resuming app")
    device.resume(pid)
    if manual:
        print("[~] Collecting data, give user input now...")
        print("[~] Press Enter to continue")
        input()
    else:
        log(f"[~] waiting {monkey_delay} seconds")
        time.sleep(monkey_delay)
        if custom_input:
            log("[~] Starting monkey")
            result = subprocess.run(
                ["adb", "shell", "monkey", "-p", package_name, "500"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            log("[~] Sending custom random input")
            adb_random_input.run(5)
        time.sleep(5)
        if result.returncode != 0:
            log("[~] Monkey returned with status 1 (Error)")
        else:
            log("[~] Finished")
    log("[~] Terminating processes")
    p_interceptor.terminate()
    p_spear.terminate()
    if install:
        log("[~] Uninstalling app")
        subprocess.run(["adb", "uninstall", package_name],
                       stdout=subprocess.DEVNULL)
        subprocess.run(
            ["adb", "shell", 'su -c "rm /data/media/0/Android/obb/*.obb"'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log("[~] Analysing pcaps")
    try:
        total, total_dec = compare(ENC_PATH, DEC_PATH)
    except ValueError as e:
        print(f"{app}: Found decrypted stream that was not encrypted!")
    if total != 0:
        quota = float(total_dec)/float(total)
        print(f"{app}: Total: {total}, decrypted: {total_dec}, Quota: {quota:.0%}")
    else:
        print(f"{app}: No streams found")

    if not keep_files:
        log("[~] Removing pcaps")
        os.remove(ENC_PATH)
        os.remove(DEC_PATH)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Try ssl_interceptor on app")
    parser.add_argument("app", metavar="<path to apk/app name>")
    parser.add_argument("-v", "--verbose", required=False,
                        action="store_const", const=True, help="Show verbose output")
    parser.add_argument("-k", "--keep_files", required=False,
                        action="store_const", const=True, help="Keep the pcaps")
    parser.add_argument("-d", "--monkey_delay",
                        metavar="<delay>", type=int, default=5, required=False, help="Delay the input generated by monkey (in seconds)")
    parser.add_argument("-u", "--manual", action="store_const", required=False,
                        const=True, help="Don't use monkey, but manual user input")
    parser.add_argument("-c", "--custom_input", action="store_true",
                        required=False, help="Use custom input engine instead of monkey")
    parser.add_argument("-i", "--install",
                        action="store_const", const=True, required=False, help="Install the apk from the given path and remove it afterwards")
    parser.add_argument("-e", "--enable_spawn_gating", action="store_const", const=True, required=False,
                        help="Enable spawn gating. Can catch spawned services, but can also lead to false negatives/positives because of unrelated processes")

    parsed = parser.parse_args()

    if parsed.manual and parsed.custom_input:
        print("Can't have -u and -c!")
        sys.exit(1)

    evaluate(parsed.app, parsed.verbose,
             parsed.keep_files, parsed.monkey_delay, parsed.install, parsed.manual, parsed.enable_spawn_gating, parsed.custom_input)
