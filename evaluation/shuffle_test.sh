ls -d ~/apk_collection/successful/* | shuf -n20 | xargs -n 1 -I {} python evaluate_app.py {} -i -c
