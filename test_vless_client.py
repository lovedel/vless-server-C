import asyncio
import websockets
import socket
import struct
import sys

UUID = "03cbc571-2867-423e-8f0a-7ea9dde7f239"

def uuid_bytes(uuid: str) -> bytes:
    return bytes.fromhex(uuid.replace("-", ""))

def build_vless_header_tcp(host: str, port: int, payload: bytes = b"") -> bytes:
    buf = bytearray()
    buf.append(0x01)
    buf.extend(uuid_bytes(UUID))
    buf.append(0x00)
    buf.append(0x01)
    buf.extend(struct.pack("!H", port))
    buf.append(0x02)
    buf.append(len(host))
    buf.extend(host.encode())
    buf.extend(payload)
    return bytes(buf)

async def run(ws_port: int):
    uri = f"ws://127.0.0.1:{ws_port}"
    host = "httpbin.org"
    port = 80
    http_req = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
    header = build_vless_header_tcp(host, port, http_req)
    print(f"Sending {len(header)} bytes to {uri}")
    async with websockets.connect(uri, max_size=None) as ws:
        await ws.send(header)
        try:
            while True:
                msg = await asyncio.wait_for(ws.recv(), timeout=10)
                if isinstance(msg, bytes):
                    print(f"Got {len(msg)} bytes: {msg[:100]}")
                else:
                    print(f"Got text: {msg[:100]}")
        except asyncio.TimeoutError:
            print("Timeout - no more data")
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed")

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 28787
    asyncio.run(run(port))
