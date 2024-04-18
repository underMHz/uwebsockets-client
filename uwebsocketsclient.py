'''
Websockets client for micropython (with SSL/TLS)
Based very heavily on
https://gist.github.com/laurivosandi/2983fe38ad7aff85a5e3b86be8f00718
'''
import ubinascii as binascii
import urandom as random
import ure as re
import ustruct as struct
import usocket as socket
from ucollections import namedtuple

import ussl as ssl
import uos

# Opcodes
OP_CONT = const(0x0)
OP_TEXT = const(0x1)
OP_BYTES = const(0x2)
OP_CLOSE = const(0x8)
OP_PING = const(0x9)
OP_PONG = const(0xa)

# Close codes
CLOSE_OK = const(1000)
CLOSE_GOING_AWAY = const(1001)
CLOSE_PROTOCOL_ERROR = const(1002)
CLOSE_DATA_NOT_SUPPORTED = const(1003)
CLOSE_BAD_DATA = const(1007)
CLOSE_POLICY_VIOLATION = const(1008)
CLOSE_TOO_BIG = const(1009)
CLOSE_MISSING_EXTN = const(1010)
CLOSE_BAD_CONDITION = const(1011)

'''
Parse the received URI element by element
'''
URI = namedtuple('URI', ['hostname', 'port', 'path'])

def urlparse(uri):
    URL_RE = re.compile(r'(ws|wss)://([A-Za-z0-9\-\.]+)(?:\:([0-9]+))?(/.+)?')
    match = URL_RE.match(uri)
    if match:
        hostname = match.group(2)
        port = int(match.group(3)) if match.group(3) else None
        path = match.group(4) if match.group(4) else "/"
        return URI(hostname, port, path)
    else:
        raise ValueError(f'Invalid URL: {uri}')

'''
Extract and save intermediate certificate from imported CA certificate (.crt)

Get the certificate
No text files other than certificates should be placed in the listing directory.
Download the .crt certificate for the site you want to access in advance and upload it to Pi pico.
'''
def get_cadata():
    dir_path = '/lib/'
    listdir = uos.listdir(dir_path)

    if any(".crt" in filename for filename in listdir):
        crt_file_path = [filename for filename in listdir if filename.endswith(".crt")]
        
        if len(crt_file_path) == 1:
            crt_file_path = dir_path + crt_file_path[0]
            txt_file_path = crt_file_path[:-3] + "txt"
            uos.rename(crt_file_path, txt_file_path)

            f = open(txt_file_path)
            content = f.read()
            
            def certificate_parse(content):
                lines = content.split('\r\n')
                # Delete first and last lines
                if lines:
                    del lines[0]
                if lines:
                    del lines[-1]
                # Create new string by concatenating split lines
                content = '\r\n'.join(lines)
                
                return content
            
            content = certificate_parse(content)

            regex_pattern = r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----'
            regex = re.compile(regex_pattern)
            match = regex.search(content)
            
            if match:
                intermediate_certificate = match.group(1)
                ca_data_base64 = certificate_parse(intermediate_certificate)
                
                f = open(txt_file_path, 'w+')
                f.write(ca_data_base64)
                
                return ca_data_base64
            
            else:
                print('Error: Intermediate certificate not found.')
                
        else:
            print("Error: Multiple .crt files found.")

    else:
        txt_file_path = [filename for filename in listdir if filename.endswith(".txt")]
        txt_file_path = dir_path + txt_file_path[0]
        
        f = open(txt_file_path)
        ca_data_base64 = f.read()
        
        return ca_data_base64

class Websocket:
    is_client = False

    def __init__(self, sock):
        self._sock = sock
        self.open = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def settimeout(self, timeout):
        self._sock.settimeout(timeout)

    def read_frame(self, max_size=None):

        # Frame header
        byte1, byte2 = struct.unpack('!BB', self._sock.read(2))

        # Byte 1: FIN(1) _(1) _(1) _(1) OPCODE(4)
        fin = bool(byte1 & 0x80)
        opcode = byte1 & 0x0f

        # Byte 2: MASK(1) LENGTH(7)
        mask = bool(byte2 & (1 << 7))
        length = byte2 & 0x7f

        if length == 126:  # Magic number, length header is 2 bytes
            length, = struct.unpack('!H', self._sock.read(2))
        elif length == 127:  # Magic number, length header is 8 bytes
            length, = struct.unpack('!Q', self._sock.read(8))

        if mask:  # Mask is 4 bytes
            mask_bits = self._sock.read(4)

        try:
            data = self._sock.read(length)
        except MemoryError:
            # We can't receive this many bytes, close the socket
            self.close(code=CLOSE_TOO_BIG)
            return True, OP_CLOSE, None

        if mask:
            data = bytes(b ^ mask_bits[i % 4]
                         for i, b in enumerate(data))

        return fin, opcode, data

    def write_frame(self, opcode, data=b''):

        fin = True
        mask = self.is_client  # messages sent by client are masked

        length = len(data)

        # Frame header
        # Byte 1: FIN(1) _(1) _(1) _(1) OPCODE(4)
        byte1 = 0x80 if fin else 0
        byte1 |= opcode

        # Byte 2: MASK(1) LENGTH(7)
        byte2 = 0x80 if mask else 0

        if length < 126:  # 126 is magic value to use 2-byte length header
            byte2 |= length
            self._sock.write(struct.pack('!BB', byte1, byte2))

        elif length < (1 << 16):  # Length fits in 2-bytes
            byte2 |= 126  # Magic code
            self._sock.write(struct.pack('!BBH', byte1, byte2, length))

        elif length < (1 << 64):
            byte2 |= 127  # Magic code
            self._sock.write(struct.pack('!BBQ', byte1, byte2, length))

        else:
            raise ValueError()

        if mask:  # Mask is 4 bytes
            mask_bits = struct.pack('!I', random.getrandbits(32))
            self._sock.write(mask_bits)

            data = bytes(b ^ mask_bits[i % 4]
                         for i, b in enumerate(data))

        self._sock.write(data)

    def recv(self):
        assert self.open

        while self.open:
            try:
                fin, opcode, data = self.read_frame()
            except ValueError:
                self._close()
                return

            if not fin:
                raise NotImplementedError()

            if opcode == OP_TEXT:
                return data.decode('utf-8')
            elif opcode == OP_BYTES:
                return data
            elif opcode == OP_CLOSE:
                self._close()
                return
            elif opcode == OP_PONG:
                # Ignore this frame, keep waiting for a data frame
                continue
            elif opcode == OP_PING:
                # We need to send a pong frame
                self.write_frame(OP_PONG, data)
                # And then wait to receive
                continue
            elif opcode == OP_CONT:
                # This is a continuation of a previous frame
                raise NotImplementedError(opcode)
            else:
                raise ValueError(opcode)

    def send(self, buf):

        assert self.open

        if isinstance(buf, str):
            opcode = OP_TEXT
            buf = buf.encode('utf-8')
        elif isinstance(buf, bytes):
            opcode = OP_BYTES
        else:
            raise TypeError()

        self.write_frame(opcode, buf)

    def close(self, code=CLOSE_OK, reason=''):

        if not self.open:
            return

        buf = struct.pack('!H', code) + reason.encode('utf-8')

        self.write_frame(OP_CLOSE, buf)
        self._close()

    def _close(self):
        self.open = False
        self._sock.close()

class WebsocketClient(Websocket):
    is_client = True

'''
Connect a websocket
'''
def connect(uri):
    # URI parse
    uri = urlparse(uri)
    assert uri
    # Encode certificates got from PEM files
    ca_data_base64 = get_cadata()
    ca_data = binascii.a2b_base64(ca_data_base64.encode("utf-8"))
    # Connect
    sock = socket.socket()
    addr = socket.getaddrinfo(uri.hostname, uri.port)
    sock.connect(addr[0][4])
    
    tls_socket = ssl.wrap_socket(sock, server_side=False, cert_reqs=ssl.CERT_REQUIRED, cadata=ca_data, server_hostname=uri.hostname)
    tls_socket.setblocking(True)
    
    # Sec-WebSocket-Key is 16 bytes of random base64 encoded
    key = binascii.b2a_base64(bytes(random.getrandbits(8)
                                    for _ in range(16)))[:-1]
    
    tls_socket.write(f'GET {uri.path} HTTP/1.1\r\n')
    tls_socket.write(f'Host: {uri.hostname}:{uri.port}\r\n')
    tls_socket.write('Upgrade: websocket\r\n')
    tls_socket.write('Connection: Upgrade\r\n')
    tls_socket.write('Sec-WebSocket-Version: 13\r\n')
    tls_socket.write(f'Sec-WebSocket-Key: {key}\r\n')
    tls_socket.write('\r\n')

    header = tls_socket.readline()[:-2]
    assert header == b'HTTP/1.1 101 Switching Protocols', header
    
    # We don't (currently) need these headers
    # FIXME: should we check the return key?
    while header:
        header = tls_socket.readline()[:-2]

    return WebsocketClient(tls_socket)
