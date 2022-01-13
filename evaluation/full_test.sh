APKS=$(ls -d ~/apk_collection/successful/* | tail -n 1841)
for f in $APKS
do
    adb shell ps -e | grep frida-server-12 > /dev/null
    if [ $? -eq 1 ]; then
        adb shell su -c /data/local/tmp/frida-server-12 &
    fi
    python3 evaluate_app.py $f -i -c
    if [ $? -ne 0 ]; then
        >&2 echo "Evalute error"
        break
    fi
done






# ls -d ~/apk_collection/successful/* | tail -n 1841 | xargs -n 1 -I {} python evaluate_app.py {} -i -c
