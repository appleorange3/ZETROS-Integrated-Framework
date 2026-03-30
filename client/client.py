import socket
import time
import hmac
import hashlib
from identity import get_device_id, get_device_secret

HOST = '127.0.0.1'
PORT = 5000

def generate_hmac(challenge, key):
    return hmac.new(
        key.encode(),
        str(challenge).encode(),
        hashlib.sha256
    ).hexdigest()

device_id = get_device_id()
device_secret = get_device_secret()

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Try auth
client.send(f"HELLO {device_id}".encode())
data = client.recv(1024).decode()

# Register
if data == "NOT_REGISTERED":
    print("Registering device...")
    client.close()

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    client.send(f"REGISTER {device_id} {device_secret}".encode())
    print(client.recv(1024).decode())
    client.close()
    exit()

# Auth
if data.startswith("CHALLENGE"):
    challenge = int(data.split()[1])

    response = generate_hmac(challenge, device_secret)
    client.send(response.encode())

    result = client.recv(1024).decode()

    if result != "AUTH_SUCCESS":
        print("Auth failed ❌")
        exit()

    print("Authenticated ✅")

# Communication loop
while True:
    try:
        client.send("sensor_data".encode())

        response = client.recv(1024)

        if not response:
            print("Server closed connection")
            break

        response = response.decode()

        if response == "BLOCKED":
            print("Device blocked 🚫")
            break

        print("Server:", response)

        time.sleep(0.1)

    except ConnectionAbortedError:
        print("Connection aborted by server 🚫")
        break

    except Exception as e:
        print("[CLIENT ERROR]", e)
        break