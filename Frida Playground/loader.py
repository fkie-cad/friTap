import frida
import sys
import os
import platform
import threading

f = open("agent.js","r")
agent_code = f.read()


session = frida.attach(17536)

print("After attach")
script = session.create_script(agent_code)

def on_message(message, data):
    if message['type'] == 'send':
        file_object = open('data.txt', 'a')
        print(message['payload'] )
        payload = str(data)
        #print(payload)
        file_object.write(payload)
        file_object.close()

script.on('message', on_message)

#Start loading in different thread to avoid blocking
loadingThread = threading.Thread(target=script.load)
loadingThread.start()




sys.stdin.read()
