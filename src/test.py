# scan_gen.py
import socket, time
target = "127.0.0.1"
ports = [1111, 2222, 3333, 445]
for p in ports:
    try:
        s = socket.socket()
        s.settimeout(0.6)
        s.connect((target, p))
        s.close()
    except:
        pass
    time.sleep(0.5)

