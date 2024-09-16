import argparse
import asyncio
import logging
import os
import struct

from pg_buffer import PgBuffer
from pg_data_types import IntField, field_factory

logging.basicConfig(format="%(levelname)s:%(name)s:%(message)s")

log = logging.getLogger(__name__)

# Dictionary mapping PostgreSQL Frontend Message codes to their descriptions
PSQL_FE_MESSAGES = {
    "p": "Password message",
    "Q": "Simple query",
    "P": "Parse",
    "B": "Bind",
    "E": "Execute",
    "D": "Describe",
    "C": "Close",
    "H": "Flush",
    "S": "Sync",
    "F": "Function call",
    "d": "Copy data",
    "c": "Copy completion",
    "f": "Copy failure",
    "X": "Termination",
}

SSL_BODY_MAGIC_NUMBER = 80877103
SSL_BODY_SIZE = 8

AUTH_KERBEROS_V5 = 2
AUTH_PLAIN_TEXT = 3
AUTH_MD5 = 5


# Class to handle PostgreSQL communication asynchronously
class AsyncPsqlHandler:
    __slots__ = ("reader", "writer", "pgbuf", "prepared_statements", "args")

    def __init__(self, reader, writer, args):
        self.reader = reader
        self.writer = writer
        self.pgbuf = PgBuffer(reader, writer)
        self.args = args
        self.prepared_statements = {}  # Store prepared statements

    async def handle(self):
        try:
            await self.read_ssl_request()
            await self.send_ssl_response()
            # Send standard PostgreSQL startup messages
            await self.read_startup_message()

            if self.args.auth == "plain":
                await self.send_plain_text_authentication_request()
            elif self.args.auth == "md5":
                await self.send_md5_authentication_request()
            else:
                raise ValueError("Unsupported auth type {}".format(args.auth))
            await self.read_authentication()
            await self.send_authentication_ok()

            await self.send_initial_parameters()
            await self.send_backend_key_data()

            await self.send_ready_for_query()

            # Main loop to handle incoming messages
            while True:
                type_code = await self.pgbuf.read_byte()

                if type_code == b"Q":
                    await self.handle_query()
                    await self.send_ready_for_query()
                elif type_code == b"P":
                    await self.handle_parse()
                elif type_code == b"B":
                    await self.handle_bind()
                elif type_code == b"D":
                    await self.handle_describe()
                elif type_code == b"E":
                    await self.handle_execute()
                elif type_code == b"S":
                    await self.handle_sync()
                    await self.send_ready_for_query()
                elif type_code == b"C":
                    await self.handle_close()
                elif type_code == b"X":
                    print("Termination requested")
                    break
                else:
                    print(f"Unhandled message type: {type_code}")
                    # TODO: Handle other message types
                    # length = await self.pgbuf.read_int32()
                    # await self.pgbuf.read_bytes(length - 4)
        except Exception as e:
            print(f"Error: {e}")
            raise
        finally:
            self.writer.close()
            await self.writer.wait_closed()

    async def handle_bind(self):
        # Read message length
        msglen = await self.pgbuf.read_int32()

        # Read portal name and prepared statement name (both are null-terminated)
        portal_name = await self.read_null_terminated_string()
        prepared_statement_name = await self.read_null_terminated_string()
        # breakpoint()

        # Read the number of parameter format codes
        num_format_codes = await self.pgbuf.read_int16()
        format_codes = [
            await self.pgbuf.read_int16() for _ in range(num_format_codes)
        ]

        # Read the number of parameters
        num_parameters = await self.pgbuf.read_int16()
        parameters = [
            await self.pgbuf.read_bytes(await self.pgbuf.read_int32())
            for _ in range(num_parameters)
        ]

        # Read the number of result format codes
        num_result_format_codes = await self.pgbuf.read_int16()
        result_format_codes = [
            await self.pgbuf.read_int16() for _ in range(num_result_format_codes)
        ]

        print(
            f"Bound portal {portal_name} to prepared statement {prepared_statement_name} with params: {parameters}"
        )

        # Store the portal details
        self.prepared_statements[portal_name].update(
            {"statement_name": prepared_statement_name, "parameters": parameters}
        )

        # Send Bind Complete response
        await self.send_bind_complete()

    def write(self, buffer):
        # self.debug(buffer)
        self.writer.write(buffer)

    def debug(self, b):
        # if b[0] == 49:
        #    raise Exception('falha')
        print("-." * 20)
        print([hex(x) for x in b])
        print("-." * 20)

    async def send_bind_complete(self):
        print("send_bind_complete")
        # self.debug(struct.pack("!ci", b"2", 4))
        self.write(struct.pack("!ci", b"2", 4))  # '2' for BindComplete
        await self.writer.drain()

    async def read_null_terminated_string(self):
        data = bytearray()
        while True:
            byte = await self.pgbuf.read_byte()
            if byte == b"\x00":  # Null terminator
                break
            data.extend(byte)
        return data.decode()

    async def handle_describe(self):
        # Read message length
        msglen = await self.pgbuf.read_int32()

        # Read the type of description ('S' for statement, 'P' for portal)
        desc_type = await self.pgbuf.read_byte()
        desc_name = await self.pgbuf.read_bytes_until_null()

        if desc_type == b"S":
            # Describe a prepared statement
            prepared_statement = self.prepared_statements.get(desc_name)
            if not prepared_statement:
                raise Exception(f"Prepared statement {desc_name} not found.")

            # Send RowDescription message
            await self.send_row_description(
                [IntField("a"), IntField("b")]
            )  # Modify based on your schema
        elif desc_type == b"P":
            # Describe a portal
            print(desc_name)
            portal = self.prepared_statements.get(desc_name)
            if not portal:
                raise Exception(f"Portal {desc_name} not found.")

            # Send RowDescription message for the portal
            await self.send_row_description(
                [IntField("a"), IntField("b")]
            )  # Modify based on your schema

        # Send Describe Complete
        await self.send_describe_complete()

    async def send_describe_complete(self):
        self.write(struct.pack("!ci", b"3", 4))  # '3' for DescribeComplete
        await self.writer.drain()

    async def handle_execute(self):
        # Read the length of the entire Execute message
        msglen = await self.pgbuf.read_int32()
        # The length field itself is 4 bytes, so the message length is msglen - 4
        actual_msg_length = msglen - 4

        # Read the portal name (null-terminated string)
        portal_name = await self.read_null_terminated_string()

        # Read the number of rows to execute (Int32)
        max_rows = await self.pgbuf.read_int32()

        # Validate the length of the remaining message body
        remaining_length = (
            actual_msg_length - len(portal_name) - 4
        )  # 4 bytes for max_rows
        if remaining_length < 0:
            raise Exception("Message length mismatch")

        print(
            f"exec, {portal_name=}, {max_rows=}, {remaining_length=}, {actual_msg_length=}, {msglen=}"
        )
        # Look up the portal in prepared_statements
        portal = self.prepared_statements.get(portal_name)
        if not portal:
            # Handle error: portal not found
            await self.send_error(
                "FATAL", "XX000", f"Portal {portal_name} not found."
            )
            return

        print("=" * 20)
        print(self.prepared_statements)
        print("=" * 20)
        sql = portal["query"]  # Assuming portal contains the query
        if sql.strip().startswith("SET"):
            # Handle SET command
            # For example, you might want to parse and apply the setting
            print(f"Executing SET command: {sql}")

            # Send CommandComplete message
            await self.send_command_complete("SET\x00".encode())
        else:
            print(f"Executing portal {portal_name}, max_rows: {max_rows}")
            # Execute the query associated with the portal
            # For now, this is a mock implementation
            # You should replace this with actual query execution based on the portal
            rows = [[1, 2], [3, 4], [5, 6]] if max_rows == 0 else [[1, 2]]

            # Send RowData for the rows
            await self.send_row_data(rows)

            # Send CommandComplete message
            await self.send_command_complete("SELECT\x00".encode())

        # Optionally, send ReadyForQuery after completion
        # await self.send_ready_for_query()

    async def send_command_complete(self, tag):
        print("send_command_complte", tag)
        # await self.debug(struct.pack("!ci", b"C", 4 + len(tag)))
        self.write(struct.pack("!ci", b"C", 4 + len(tag)))
        self.write(tag)
        # await self.debug(tag)
        await self.writer.drain()

    async def handle_sync(self):
        msglen = await self.pgbuf.read_int32()
        print(">>>>>>>>>>>", "SYNC", msglen)

    async def send_ready_for_query(self):
        # print(">>> ReadToQuery")
        # 'Z' for ReadyForQuery, 'I' for Idle
        self.write(struct.pack("!cic", b"Z", 5, b"I"))
        await self.writer.drain()

    async def handle_close(self):
        # Read message length
        msglen = await self.pgbuf.read_int32()

        # Read close type ('S' for statement, 'P' for portal)
        close_type = await self.pgbuf.read_byte()
        close_name = await self.pgbuf.read_parameters(1)

        if close_type == b"S":
            self.prepared_statements.pop(close_name, None)
        elif close_type == b"P":
            self.prepared_statements.pop(close_name, None)

        # Send Close Complete response
        await self.send_close_complete()

    async def send_close_complete(self):
        self.write(struct.pack("!ci", b"3", 4))  # '3' for CloseComplete
        await self.writer.drain()

    async def handle_parse(self):
        # Read the length of the entire Parse message
        _ = await self.pgbuf.read_int32()

        # Read the prepared statement name (can be an empty string)
        prepared_statement_name = await self.pgbuf.read_bytes_until_null()

        # Read the query string
        query = await self.pgbuf.read_bytes_until_null()

        # Read the number of parameter types (Int16)
        num_parameter_types = await self.pgbuf.read_int16()

        # Initialize a list for the parameter types
        parameter_types = []

        # Read each parameter type (Int32 OIDs)
        for _ in range(num_parameter_types):
            param_type = await self.pgbuf.read_int32()
            parameter_types.append(field_factory("", param_type))

        # For now, let's just log the Parse message details
        # TODO: Validate prepared statement
        log.info(
            "Parse: Statement Name:%s , Query: %s , Parameter Types: %s",
            prepared_statement_name,
            query,
            parameter_types,
        )

        # Save the query associated with the statement name
        self.prepared_statements[prepared_statement_name] = {
            "query": query,
            "parameter_types": parameter_types,
        }
        await self.send_parse_complete()

    async def send_parse_complete(self):
        self.write(struct.pack("!ci", b"1", 4))
        await self.writer.drain()

    async def handle_query(self):
        msglen = await self.pgbuf.read_int32()
        sql = await self.pgbuf.read_bytes(msglen - 4)
        print("SQL: ", sql)
        # Check if the command is BEGIN
        if sql.upper() == b"BEGIN\x00":
            print("BEGIN command received")
            # Send Command Complete message with 'BEGIN'
            await self.send_command_complete(b"BEGIN\x00")
            # Send Ready for Query message indicating the server is ready
            # await self.send_ready_for_query()
        else:
            await self.query(sql)

    async def read_ssl_request(self):
        msglen = await self.pgbuf.read_int32()
        sslcode = await self.pgbuf.read_int32()
        if msglen != SSL_BODY_SIZE or sslcode != SSL_BODY_MAGIC_NUMBER:
            raise Exception("Unsupported SSL request")

    async def read_startup_message(self):
        msglen = await self.pgbuf.read_int32()
        version = await self.pgbuf.read_int32()
        v_maj = version >> 16
        v_min = version & 0xFFFF

        msg = await self.pgbuf.read_parameters(msglen - 8)
        # TODO: Store inicialization parameters, such as username, schema,
        # locale, etc
        print(f"Client PSQL {v_maj}.{v_min} - {msg}")

    async def read_authentication(self):
        type_code = await self.pgbuf.read_byte()
        if type_code != b"p":
            await self.send_error("FATAL", "28000", "Authentication failure")
            raise Exception(
                f"Only 'Password' auth is supported, got {type_code!r}"
            )

        msglen = await self.pgbuf.read_int32()
        password = await self.pgbuf.read_bytes(msglen - 4)

        # TODO: Test if it is a valid password
        if password != "sp33d":
            pass
        else:
            # TODO: send error message
            pass
        # TODO: Implement other auth mechanisms

    async def consume_unhandled_message(self):
        length = await self.pgbuf.read_int32()
        await self.pgbuf.read_bytes(length - 4)

    async def send_ssl_response(self):
        """Send SSL Response.
        b"N" means "Unwilling to perform SSL"
        TODO: Implement server side SSL support
        """
        self.write(b"N")
        await self.writer.drain()

    async def send_plain_text_authentication_request(self):
        """
        Message structure: R83:
            'R', message type as an authentication request (clear text)
            8 (bytes) for the total length of the message
            3 for the remaining integer, indicating a request for a clear text password.
        """
        self.write(struct.pack("!cii", b"R", 8, AUTH_PLAIN_TEXT))
        await self.writer.drain()

    async def send_md5_authentication_request(self):
        """ """
        salt = os.urandom(4)  # PostgreSQL uses a 4-byte random salt
        self.write(
            struct.pack(
                "!cII4s", b"R", 8 + 4, 5, salt
            )  # 8 bytes: length + md5 message + salt
        )
        await self.writer.drain()

    async def send_authentication_ok(self):
        self.write(struct.pack("!cii", b"R", 8, 0))  # Authentication successful
        await self.writer.drain()

    # async def send_ready_for_query(self):
    #     self.write(struct.pack("!cic", b'Z', 5, b'I'))  # Ready for query
    #     await self.writer.drain()

    # async def send_command_complete(self, tag):
    #     # Command Complete message format: 'C' <int32 length> <tag>
    #     self.write(struct.pack("!ci", b'C', 4 + len(tag)))
    #     self.write(tag)
    #     await self.writer.drain()

    async def send_error(self, severity, code, message):
        buf = PgBuffer()
        buf.write_byte(b"S")
        buf.write_string(severity)
        buf.write_byte(b"C")
        buf.write_string(code)
        buf.write_byte(b"M")
        buf.write_string(message)
        data = buf.get_buffer()

        self.write(b"E")
        self.write(struct.pack("!i", 4 + len(data)))
        self.write(data)
        await self.writer.drain()

    async def send_row_description(self, fields):
        buf = PgBuffer()
        for field in fields:
            buf.write_string(field.name)
            buf.write_int32(0)  # Table ID
            buf.write_int16(0)  # Column ID
            buf.write_int32(field.type_id)
            buf.write_int16(field.type_size)
            buf.write_int32(-1)  # Type modifier
            buf.write_int16(0)  # Text format code
        data = buf.get_buffer()

        self.write(b"T")
        self.write(struct.pack("!ih", 6 + len(data), len(fields)))
        self.write(data)
        await self.writer.drain()

    async def send_row_data(self, rows):
        for row in rows:
            buf = PgBuffer()
            for field in row:
                v = str(field).encode()
                buf.write_int32(len(v))
                buf.write_bytes(v)
            data = buf.get_buffer()

            self.write(b"D")
            self.write(struct.pack("!ih", 6 + len(data), len(row)))
            self.write(data)
        await self.writer.drain()

    async def query(self, sql):
        fields = [IntField("a"), IntField("b")]  # Define column headers
        rows = [[1, 2], [3, 4], [5, 6]]  # Example result set

        # 1. Send row description (Column names and types)
        await self.send_row_description(fields)

        # 2. Send actual rows
        await self.send_row_data(rows)

        # 3. Send command complete with a valid completion tag, e.g., "SELECT n"
        await self.send_command_complete(
            b"SELECT 3\x00"
        )  # Indicates 3 rows returned

        # 4. Send Ready for Query (status indicator)
        # await self.send_ready_for_query()

    async def send_parameter_status(self, parameter, value):
        message = f"{parameter}\x00{value}\x00".encode()
        self.write(b"S")
        self.write(struct.pack("!I", len(message) + 4))
        self.write(message)
        await self.writer.drain()

    async def send_backend_key_data(self):
        self.write(b"K")
        # TODO: Secret Key must be a configuration option
        server_secret_key = 5678
        self.write(
            struct.pack("!III", 12, os.getpid(), server_secret_key)
        )  # Process ID and secret key
        await self.writer.drain()

    async def send_initial_parameters(self):
        # Sending a set of initial parameter status messages
        # TODO: Review these parameters
        parameters = {
            "server_version": "9.6.10",
            "server_encoding": "UTF8",
            "client_encoding": "UTF8",
            "application_name": "psql",
            "is_superuser": "on",
            "session_authorization": "postgres",
            "DateStyle": "ISO, DMY",
            "IntervalStyle": "postgres",
            "TimeZone": "UTC",
            "integer_datetimes": "on",
            "standard_conforming_strings": "on",
        }
        for param, value in parameters.items():
            await self.send_parameter_status(param, value)


# Main server handling
async def handle_client(reader, writer, args):
    handler = AsyncPsqlHandler(reader, writer, args)
    await handler.handle()


async def main(args):
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, args),
        args.bind,
        args.port,
    )
    addr = server.sockets[0].getsockname()
    print(f"Server running on {addr}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lemon Proxy")
    parser.add_argument(
        "-b",
        "--bind",
        help="Address to bind server",
        required=False,
        default="localhost",
    )
    parser.add_argument(
        "-p",
        "--port",
        help="Port to bind",
        required=False,
        default=5432,
        type=int,
    )
    parser.add_argument(
        "-a",
        "--auth",
        required=False,
        default="plain",
        help="Client authentication method (plain, md5)",
        choices=["plain", "md5"],
    )
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("Server stopped")
