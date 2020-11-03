adb shell pm list packages -3| awk -F ":" '{print $2}' | xargs -n1 adb uninstall            
