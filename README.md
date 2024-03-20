## 📡 uwebsockets-client
Websoket connection as client with Raspberry pi pico W (Micropython) considering SSL/TLS authentication.

----

## 🔧 Development environment

・MicroPython(v1.20.0)

・Thonny(v4.1.4)

----

## 📂 File configuration

- Please Google how to download crt.(Chain) by yourself.

RASPBERRY PI PICO<br>
│&nbsp;&nbsp;main.py<br>
│&nbsp;&nbsp;hogehoge.crt<br>
│<br>
└─lib<br>
&nbsp;&nbsp;&nbsp;&nbsp;uwebsockets-client.py<br>

----

## 📝 Example (main.py)

```python
from uwebsockets-client import connect

uri = "wss://piyopiyo.net:443/v1/ws"

# Connect the WebSocket
websocket = connect(uri)

try:
    while True:
        # recieve data
        data = websocket.recv()
        if data is not None:
            print(data)

except KeyboardInterrupt:
    print("Keyboard interrupt received, closing connection.")

finally:
    # Close the WebSocket
    websocket.close()
```
