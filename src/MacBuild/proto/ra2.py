#!/usr/bin/python
from queue import Queue, Empty
import threading
import subprocess
import getpass





def enqueue_output(out, queue):
    for line in iter(out.readline, b''):
        queue.put(line)
    out.close()

def getOutput(outQueue):
    outStr = ''
    try:
        while True: #Adds output from the Queue until it is empty
            outStr+=outQueue.get_nowait()

    except Empty:
        return outStr


username = input("Username: " )
passwd = getpass.getpass("Password: ")

cmd = ["/usr/bin/su", "-", username.strip(), "-c", "/bin/top -l 1"]

p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1)

outQueue = Queue()
errQueue = Queue()

outThread = threading.Thread(target=enqueue_output, args=(p.stdout, outQueue))
errThread = threading.Thread(target=enqueue_output, args=(p.stderr, errQueue))

outThread.daemon = True
errThread.daemon = True

outThread.start()
errThread.start()

# p.stdin.write("\n")
# p.stdin.flush()
p.stdin.write(passwd)
p.stdin.flush()

errors = getOutput(errQueue)
output = getOutput(outQueue)

print("---")
print(output)
print("---")
print(errors)
