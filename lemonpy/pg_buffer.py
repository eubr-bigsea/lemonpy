from io import BytesIO
import struct


class PgBuffer:
    """
    Buffer class to handle reading and writing data from the PostgreSQL protocol
    """

    def __init__(self, reader=None, writer=None):
        self.reader = reader
        self.writer = writer
        self.buffer = BytesIO()

    async def read_bytes(self, n):

        data = await self.reader.read(n)
        if not data:
            if self.reader.at_eof():
                raise EOFError('Client closed the connection')
            raise Exception("No data")
            #print('!!!! NO DATA !!!!', self.reader.at_eof())
        return data

    async def read_bytes_until_null(self):
        result = bytearray()
        while True:
            byte = await self.read_byte()
            if byte == b"\x00":
                break
            result.extend(byte)
        return (
            result.decode()
        )  # Or return as a byte array depending on your need

    async def read_byte(self):
        return await self.read_bytes(1)

    async def read_int32(self):
        data = await self.read_bytes(4)
        return struct.unpack("!i", data)[0]

    async def read_int16(self):
        # Read 2 bytes from the reader
        data = await self.read_bytes(2)
        # Unpack as a 16-bit signed integer using big-endian format ('!h')
        return struct.unpack("!h", data)[0]

    async def read_parameters(self, n):
        data = await self.read_bytes(n)
        return data.strip(b'\x00').split(b"\x00")

    def write_byte(self, value):
        self.buffer.write(value)

    def write_bytes(self, value):
        self.buffer.write(value)

    def write_int16(self, value):
        self.buffer.write(struct.pack("!h", value))

    def write_int32(self, value):
        self.buffer.write(struct.pack("!i", value))

    def write_int64(self, value):
        # Verifica se o valor está dentro do limite de um int64
        if not (-9223372036854775808 <= value <= 9223372036854775807):
            raise ValueError("Out of range value for an int64")

        # Converte o inteiro para bytes em ordem de bytes big-endian
        self.buffer.write(struct.pack('!q', value))

    def write_string(self, value):
        if isinstance(value, str):
            value = value.encode()
        self.buffer.write(value)
        self.buffer.write(b"\x00")

    def write_parameters(self, kvs):
        data = b"".join([f"{k}\x00{v}\x00".encode() for k, v in kvs])
        self.write_int32(4 + len(data))
        self.buffer.write(data)

    def get_buffer(self):
        return self.buffer.getvalue()

    def clear_buffer(self):
        self.buffer = BytesIO()

