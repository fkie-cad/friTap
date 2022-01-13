import subprocess
import time
import random as rnd
X_MIN = 0
X_MAX = 1440
Y_MIN = 120
Y_MAX = 2660


def run(seconds):
    """
    Will send random actions via adb and returns number of actions 
    Args:
    seconds: how long should the program run
    """
    start_time = time.time()
    actions = 0
    while True:
        state = rnd.randint(0, 2)
        if state == 0:
            subprocess.run(["adb", "shell", "input", "tap", str(
                rnd.randint(X_MIN, X_MAX)), str(rnd.randint(Y_MIN, Y_MAX))])
        elif state == 1:
            subprocess.run(["adb", "shell", "input", "swipe", str(rnd.randint(X_MIN, X_MAX)), str(
                rnd.randint(Y_MIN, Y_MAX)), str(rnd.randint(X_MIN, X_MAX)), str(rnd.randint(Y_MIN, Y_MAX))])
        actions += 1
        if time.time() - start_time >= seconds:
            break

    return actions


if __name__ == "__main__":
    print(f"{run(5)} actions")
