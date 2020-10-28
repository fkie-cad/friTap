import subprocess
import time
import random as rnd
X_MIN = 0
X_MAX = 1440
Y_MIN = 120
Y_MAX = 2660


def run(seconds):
    start_time = time.time()
    while True:
        state = rnd.randint(0, 2)
        if state == 0:
            subprocess.run("adb", "shell", "input", "tap", rnd.randint(
                X_MIN, X_MAX), rnd.randint(Y_MIN, Y_MAX))
        elif state == 1:
            subprocess.run("adb", "shell", "input", "swipe", rnd.randint(X_MIN, X_MAX), rnd.randint(
                Y_MIN, Y_MAX), rnd.randint(X_MIN, X_MAX), rnd.randint(Y_MIN, Y_MAX))
        if time.time() - start_time >= seconds:
            break

    print(time.time()-start_time)


if __name__ == "__main__":
    run(5)
