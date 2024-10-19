import argparse
import asyncio
import datetime
import hashlib
import logging
import random
import re
import secrets
import ssl
import struct
from gettext import gettext
from pathlib import Path
from typing import Any, Dict, List

import sqlglot
import sqlglot.expressions
import sqlglot.expressions as exp
import yaml
from colors import color
from pg_buffer import PgBuffer
from pg_data_types import (
    IntField,
    PostgresqlDataType,
)
from sqlglot import Expression, errors

import lemonpy.backends.postgresql as pgsql
from lemonpy.catalog.file_catalog import FileCatalog
from lemonpy.custom_types import (
    Config,
    Portal,
    PreparedStatement,
    SessionParameter,
    Source,
)
from lemonpy.parser_cmd import get_all, get_ast, optimize

logging.basicConfig(format="%(levelname)s: %(name)s: %(message)s")

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

SSL_BODY_MAGIC_NUMBER = 80877103
SSL_DISABLED = 196608
SSL_BODY_SIZE = 8

AUTH_KERBEROS_V5 = 2
AUTH_PLAIN_TEXT = 3
AUTH_MD5 = 5
CANCEL_REQUEST_CODE = 80877102

set_command_regex = re.compile(
    r"^\s*SET\s+(LOCAL\s+)?([a-zA-Z_]+(?:\.[a-zA-Z_]+)?)\s*=\s*'?(.*?)'?\s*;?$",
    re.IGNORECASE,
)

connections = {}


# Class to handle PostgreSQL communication asynchronously
class AsyncPsqlHandler:
    __slots__ = (
        "application_name",
        "args",
        "binary_transfer",
        "canceling",
        "catalog",
        "certificates",
        "client_encoding",
        "config",
        "current_database",
        "current_schema",
        "pgbuf",
        "pid",
        "prepared_statements",
        "portals",
        "reader",
        "must_send_row_description",
        "session_parameters",
        "session_secret_key",
        "settings",
        "user",
        "waiting_describe",
        "writer",
    )

    def __init__(self, reader, writer, args, config, certificates, catalog):
        self.config = config
        self.args = args

        self.reader = reader
        self.writer = writer
        self.pgbuf = PgBuffer(reader, writer)

        self.certificates = certificates
        self.catalog = catalog

        self.prepared_statements: Dict[str, PreparedStatement] = {}
        self.portals: Dict[str, Portal] = {}
        self.session_parameters: Dict[str, SessionParameter] = {}

        self.must_send_row_description = False
        self.waiting_describe = None
        self.client_encoding = "UTF8"
        self.user = None
        self.binary_transfer = False

        self.canceling = False

        self.session_secret_key = None
        self.pid = random.randint(1000, 64000)

        self.current_database = None
        self.current_schema = "public"
        self.application_name = None

    async def handle(self):
        try:
            is_cancel = await self.read_ssl_or_cancel_request()

            if is_cancel:
                process_id = await self.pgbuf.read_int32()
                secret_key = await self.pgbuf.read_int32()
                log.info(f"Cancel query for pid {process_id} {secret_key}.")
                conn = connections.get(process_id)
                if conn and conn.session_secret_key == secret_key:
                    conn.canceling = True
                    return

            await self.send_ssl_response()
            log.info("Reading startup message")

            # Send standard PostgreSQL startup messages
            await self.read_startup_message()

            if self.args.auth == "plain":
                await self.send_plain_text_authentication_request()
            elif self.args.auth == "md5":
                await self.send_md5_authentication_request()
            elif self.args.auth == "scram-sha-256":
                await self.send_scram_sha_256_authentication_request()
            else:
                raise ValueError("Unsupported auth type {}".format(args.auth))

            log.info("Waiting for client authentication")
            if not await self.read_authentication():
                await self.send_error(
                    severity="FATAL",
                    code="28P01",
                    message=gettext("password authentication failed for user"),
                )
            else:
                await self.send_authentication_ok()

                await self.send_initial_parameters()
                await self.send_backend_key_data()

                await self.send_ready_for_query()

                connections[self.pid] = self
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
                        _ = await self.pgbuf.read_int32()
                        # Read the type of description ('S' for statement, 'P' for portal)
                        desc_type = await self.pgbuf.read_byte()
                        desc_name = await self.pgbuf.read_bytes_until_null()
                        self.waiting_describe = [desc_type, desc_name]

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
        except EOFError:
            log.error("Client closed communications")
        except Exception as e:
            log.exception(e)
        finally:
            self.writer.close()
            await self.writer.wait_closed()
            connections.pop(self.pid, None)

    async def client_connected_cb(self, reader, writer):
        # This callback is required for the StreamReaderProtocol
        pass

    async def upgrade_to_ssl(self):
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(
            certfile=self.certificates[0],
            keyfile=self.certificates[1],
        )

        transport = self.writer.transport
        protocol = self.writer.transport.get_protocol()

        loop = asyncio.get_running_loop()  # Get the current running loop
        new_transport = await loop.start_tls(
            transport, protocol, ssl_context, server_side=True
        )

        # Update writer with new secure transport
        # Hack for Python 3.7
        self.writer._transport = new_transport

        # new_reader = asyncio.StreamReader()
        # new_protocol = asyncio.StreamReaderProtocol(
        #     new_reader, client_connected_cb=self.client_connected_cb
        # )
        # new_transport.set_protocol(new_protocol)

        # new_writer = asyncio.StreamWriter(
        #     new_transport, new_protocol, new_reader, loop
        # )

        # self.reader = new_reader
        # self.writer = new_writer
        # self.pgbuf = PgBuffer(new_reader, new_writer)

    def value_to_bytes(self, value: Any, data_type: int) -> bytes:
        if value is None:
            return struct.pack("!i", -1)
        elif data_type == PostgresqlDataType.BOOL:
            return b"\x01" if value else b"\x00"
        elif data_type in (
            PostgresqlDataType.INT2,
            PostgresqlDataType.INT4,
            PostgresqlDataType.INT8,
        ):
            return struct.pack("!q", value)  # Always use 8 bytes for integers
        elif data_type == PostgresqlDataType.FLOAT4:
            return struct.pack("!f", value)
        elif data_type == PostgresqlDataType.FLOAT8:
            return struct.pack("!d", value)
        elif data_type in (
            PostgresqlDataType.CHAR,
            PostgresqlDataType.VARCHAR,
            PostgresqlDataType.TEXT,
        ):
            return value  # .encode("utf-8")
        elif data_type == PostgresqlDataType.BYTEA:
            return value
        elif data_type == PostgresqlDataType.DATE:
            # Assuming value is a datetime.date object
            days = (value - datetime.date(2000, 1, 1)).days
            return struct.pack("!i", days)
        elif data_type == PostgresqlDataType.TIMESTAMP:
            # Assuming value is a datetime.datetime object
            microseconds = int(
                (value - datetime.datetime(2000, 1, 1)).total_seconds()
                * 1_000_000
            )
            return struct.pack("!q", microseconds)
        else:
            # For unhandled types, convert to string and encode
            return str(value).encode("utf-8")

    def parse_binary_parameter(self, param_data: bytes, param_type: int) -> Any:
        if param_type == PostgresqlDataType.BOOL:
            return struct.unpack("!?", param_data)[0]
        elif param_type == PostgresqlDataType.INT2:
            return struct.unpack("!h", param_data)[0]
        elif param_type == PostgresqlDataType.INT4:
            return struct.unpack("!i", param_data)[0]
        elif param_type == PostgresqlDataType.INT8:
            return struct.unpack("!q", param_data)[0]
        elif param_type == PostgresqlDataType.FLOAT4:
            return struct.unpack("!f", param_data)[0]
        elif param_type == PostgresqlDataType.FLOAT8:
            return struct.unpack("!d", param_data)[0]
        elif param_type in (
            PostgresqlDataType.CHAR,
            PostgresqlDataType.VARCHAR,
            PostgresqlDataType.TEXT,
        ):
            return param_data.decode("utf-8")
        elif param_type == PostgresqlDataType.BYTEA:
            return param_data
        elif param_type == PostgresqlDataType.DATE:
            # Dates are sent as integers representing the number of days since 2000-01-01
            days = struct.unpack("!i", param_data)[0]
            return (
                datetime.date(2000, 1, 1) + datetime.timedelta(days=days)
            ).isoformat()
        elif param_type == PostgresqlDataType.TIMESTAMP:
            # Timestamps are sent as integers representing microseconds since 2000-01-01
            microseconds = struct.unpack("!q", param_data)[0]
            return (
                datetime.datetime(2000, 1, 1)
                + datetime.timedelta(microseconds=microseconds)
            ).isoformat()
        else:
            # For unhandled types, return the raw bytes
            return param_data

    async def handle_bind(self):
        # Read message length
        _ = await self.pgbuf.read_int32()

        # Read portal name and prepared statement name (both are null-terminated)
        portal_name = await self.read_null_terminated_string()
        statement_name = await self.read_null_terminated_string()

        # Read the number of parameter format codes
        num_format_codes = await self.pgbuf.read_int16()
        format_codes = [
            await self.pgbuf.read_int16() for _ in range(num_format_codes)
        ]

        # Read the number of parameters
        num_parameters = await self.pgbuf.read_int16()
        parameters = []
        ps: PreparedStatement = self.prepared_statements.get(portal_name)

        for i in range(num_parameters):
            param_length = await self.pgbuf.read_int32()
            if param_length == -1:
                parameters.append(None)
            else:
                param_data = await self.pgbuf.read_bytes(param_length)
                # Use format code if available, otherwise default to text
                format_code = format_codes[i] if i < len(format_codes) else 0
                if format_code == 0:  # Text format
                    parameters.append(param_data.decode("utf-8"))
                else:  # Binary format
                    log.info("Binary format for parameter")
                    parameters.append(
                        self.parse_binary_parameter(
                            param_data, ps.parameter_types[i]
                        )
                    )

        # Read the number of result format codes
        num_result_format_codes = await self.pgbuf.read_int16()
        result_format_codes = [
            await self.pgbuf.read_int16() for _ in range(num_result_format_codes)
        ]

        log.info(
            "Bound portal %s to prepared statement %s with params: %s",
            portal_name,
            statement_name,
            parameters,
        )

        # Store the portal details
        # self.prepared_statements[portal_name].update(
        #     {"statement_name": prepared_statement_name, "parameters": parameters}
        # )
        if statement_name not in self.prepared_statements:
            raise ValueError(f"Prepared statement '{statement_name}' not found")
        self.portals[portal_name] = Portal(
            portal_name, statement_name, parameters, result_format_codes
        )
        # Send Bind Complete response
        await self.send_bind_complete()

    def write(self, buffer):
        self.writer.write(buffer)

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

    async def handle_describe(self, fields=None):
        # Read message length

        if fields is None:
            fields = [IntField("a"), IntField("b")]
        # Read the type of description ('S' for statement, 'P' for portal)
        desc_type, desc_name = self.waiting_describe

        if desc_type == b"S":
            # Describe a prepared statement
            prepared_statement = self.prepared_statements.get(desc_name)
            if not prepared_statement:
                raise Exception(f"Prepared statement {desc_name} not found.")

            # Send RowDescription message
            # await self.send_row_description(
            #     fields
            # )  # Modify based on your schema
        elif desc_type == b"P":
            # Describe a portal
            print(desc_name)
            portal = self.portals.get(desc_name)
            if not portal:
                raise Exception(f"Portal {desc_name} not found.")

            # Send RowDescription message for the portal
            # await self.send_row_description(
            #     fields
            # )  # Modify based on your schema
        else:
            raise Exception(f"Invalid describe type {desc_type}")

        self.must_send_row_description = True
        # Send Describe Complete
        # await self.send_describe_complete()

    # async def send_describe_complete(self):
    #     self.write(struct.pack("!ci", b"3", 4))  # '3' for DescribeComplete
    #     await self.writer.drain()

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
        if portal_name not in self.portals:
            await self.send_error(
                "FATAL", "XX000", f"Portal {portal_name} not found."
            )
            return

        # Look up the portal in prepared_statements
        ps: PreparedStatement = self.prepared_statements.get(portal_name)
        portal: Portal = self.portals.get(portal_name)

        sql = ps.query.strip("\0")  # Assuming portal contains the query

        # print("=" * 20)
        # print(self.prepared_statements)
        # print(ps)
        # print("=" * 20)

        await self._handle_query(sql, portal.parameters)

    async def send_command_complete(self, tag):
        log.info("Send command complete %s", tag)
        # await self.debug(struct.pack("!ci", b"C", 4 + len(tag)))
        self.write(struct.pack("!ci", b"C", 4 + len(tag)))
        self.write(tag)
        # await self.debug(tag)
        await self.writer.drain()

    async def handle_sync(self):
        _ = await self.pgbuf.read_int32()

    async def send_ready_for_query(self):
        self.write(struct.pack("!cic", b"Z", 5, b"I"))
        await self.writer.drain()

    async def handle_close(self):
        # Read message length
        _ = await self.pgbuf.read_int32()

        # Read close type ('S' for statement, 'P' for portal)
        close_type = await self.pgbuf.read_byte()
        close_name = await self.pgbuf.read_parameters(1)

        if close_type == b"S":
            self.prepared_statements.pop(close_name, None)
        elif close_type == b"P":
            self.portals.pop(close_name, None)

        # Send Close Complete response
        await self.send_close_complete()

    async def send_close_complete(self):
        self.write(struct.pack("!ci", b"3", 4))  # '3' for CloseComplete
        await self.writer.drain()

    async def handle_parse(self):
        # Read the length of the entire Parse message
        _ = await self.pgbuf.read_int32()

        # Read the prepared statement name (can be an empty string)
        statement_name = await self.pgbuf.read_bytes_until_null()

        # Read the query string
        query = await self.pgbuf.read_bytes_until_null()

        # Read the number of parameter types (Int16)
        num_parameter_types = await self.pgbuf.read_int16()

        # Initialize a list for the parameter types
        parameter_types = []

        # Read each parameter type (Int32 OIDs)
        for _ in range(num_parameter_types):
            param_type = await self.pgbuf.read_int32()
            # parameter_types.append(field_factory("", param_type))
            parameter_types.append(param_type)

        # For now, let's just log the Parse message details
        # TODO: Validate prepared statement
        log.info(
            "Parse: Statement Name:%s , Query: %s , Parameter Types: %s",
            statement_name,
            query,
            parameter_types,
        )

        # Save the query associated with the statement name
        # self.prepared_statements[prepared_statement_name] = {
        #     "query": query,
        #     "parameter_types": parameter_types,
        # }
        self.prepared_statements[statement_name] = PreparedStatement(
            statement_name, query, parameter_types
        )

        await self.send_parse_complete()

    async def send_parse_complete(self):
        self.write(struct.pack("!ci", b"1", 4))
        await self.writer.drain()

    async def handle_query(self):
        msglen = await self.pgbuf.read_int32()
        sql = (await self.pgbuf.read_bytes(msglen - 4)).decode().strip("\0")

        await self._handle_query(sql)

    async def _handle_query(self, sql, params=None):
        if params is None:
            params = []

        expr: Expression = None

        try:
            expr_list: List[Expression] = get_ast(sql, "postgres")
        except errors.ParseError as pe:
            e = pe.errors[0]
            await self.send_error(
                severity="ERROR",
                code="28P01",  # FIXME
                message="\n".join(
                    [
                        e.get("description"),
                        f"Line: {e.get('line')}",
                        f"Col: {e.get('col')}",
                    ]
                ),
            )
            return
        for expr in expr_list:
            if isinstance(expr, exp.Select):
                # Improving select

                # Notice: in sqlglot, catalog = database and db = schema
                new_expr = optimize(
                    expr,
                    dialect="postgres",
                    # schema=default_schema,
                    catalog=sqlglot.expressions.Identifier(
                        this=self.current_database
                    ),
                    db=sqlglot.expressions.Identifier(this=self.current_schema),
                )
                tables = get_all(new_expr, exp.Table)
                print("=" * 10)
                print(new_expr.sql())
                print(tables)
                # Here, db is schema and catalog is database
                for table in tables:
                    # Validate table db, schema and name (they are in catalog)
                    if False:
                        pass
                        # Send error
                    print(table.db, table.catalog, table.name)
                print("=" * 10)
                return await self.execute_select(new_expr.sql(), params)
            elif isinstance(expr, exp.Set):
                for set_item in expr.find_all(exp.SetItem):
                    self.set_parameter(set_item)
                    # print("=" * 20)
                    # for v in self.session_parameters.values():
                    #     print(v)
                    # print("=" * 20)
                await self.send_command_complete(b"SET\x00")
            elif isinstance(expr, exp.Use):
                parts = [
                    i.name for i in expr.find_all(sqlglot.expressions.Identifier)
                ]
                if len(parts) == 1:
                    self.current_database = parts[0]
                elif len(parts) == 2:
                    self.current_database = parts[1]
                    self.current_schema = parts[0]
                else:
                    await self.send_error(
                        severity="FATAL",
                        code="28P01",  # FIXME
                        message=gettext(
                            "Syntax error. USE accepts only "
                            "database or database.schema format"
                        ),
                    )
            else:
                # elif isinstance(expr, (exp.Insert, exp.Delete, exp.Update)):
                await self.send_error(
                    severity="FATAL",
                    code="28P01",  # FIXME
                    message=gettext(
                        "Command of type '{}' not supported".format(
                            expr.__class__.__name__
                        )
                    ),
                )
                return

    async def read_ssl_or_cancel_request(self):
        msglen = await self.pgbuf.read_int32()
        sslcode = await self.pgbuf.read_int32()
        if sslcode not in (
            SSL_DISABLED,
            SSL_BODY_MAGIC_NUMBER,
            CANCEL_REQUEST_CODE,
        ):
            raise Exception(
                f"Unsupported SSL request: {sslcode} { msglen != SSL_BODY_SIZE}"
            )
        return sslcode == CANCEL_REQUEST_CODE

    async def read_startup_message(self):
        print(">>>>>>", self.pgbuf.reader == self.reader)
        msglen = await self.pgbuf.read_int32()
        version = await self.pgbuf.read_int32()
        v_maj = version >> 16
        v_min = version & 0xFFFF

        msg = await self.pgbuf.read_parameters(msglen - 8)
        for i in range(0, len(msg), 2):
            if msg[i] == b"user":
                self.user = msg[i + 1].decode()
            elif msg[i] == b"database":
                self.current_database = msg[i + 1].decode()
            elif msg[i] == b"application_name":
                self.application_name = msg[i + 1].decode()
            elif msg[i] == b"client_encoding":
                self.client_encoding = msg[i + 1].decode()

        log.info(f"Client PSQL {v_maj}.{v_min} - {msg}")
        # Test if client supports binary encoding of cols value
        self.binary_transfer = b"binary" in msg

    async def read_authentication(self):
        type_code = await self.pgbuf.read_byte()

        if type_code != b"p":
            await self.send_error("FATAL", "28000", "Authentication failure")
            raise Exception(
                f"Only 'Password' auth is supported, got {type_code!r}"
            )

        msglen = await self.pgbuf.read_int32()
        password = (
            (await self.pgbuf.read_bytes(msglen - 4)).strip(b"\0")
        ).decode()
        current_password = b"sp33d"  # Senha em bytes
        username = b"postgres"  # Nome do usuário em bytes

        if self.args.auth == "md5":
            stored = hashlib.md5((current_password + username)).hexdigest()
            current_password = (
                "md5"
                + hashlib.md5(
                    (stored + str(self.session_secret_key)).encode()
                ).hexdigest()
            )
        elif self.args.auth == "scram-sha-256":
            # FIXME
            pass

        if password != current_password:
            return False
        return True

    async def send_ssl_response(self):
        """Send SSL Response.
        b"N" means "Unwilling to perform SSL"
        b"S" means "Willing to perform SSL".
        """
        if self.args.use_ssl:
            msg = b"S"
        else:
            msg = b"N"
        log.info("Sending SSL Response  {msg.decode()}")
        self.write(msg)
        await self.writer.drain()
        if self.args.use_ssl:
            await self.upgrade_to_ssl()

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
        salt = str(self.session_secret_key).encode()
        self.write(
            struct.pack(
                "!cII4s", b"R", 8 + 4, 5, salt
            )  # 8 bytes: length + md5 message + salt
        )
        await self.writer.drain()

    async def send_scram_sha_256_authentication_request(self):
        """ """
        raise ValueError("Not implemented")

    async def send_authentication_ok(self):
        self.write(struct.pack("!cii", b"R", 8, 0))  # Authentication successful
        await self.writer.drain()

    async def send_error(
        self, severity, code, message, file="", line=-1, command_analyser=""
    ):
        fields = [
            ("S", severity),
            ("C", code),
            ("M", message),
            ("F", file),  # File where error occurred
            ("L", str(line)),  # Line number
            ("R", command_analyser),  # Routine name
        ]
        error_body = b"".join(
            field_type.encode() + field_value.encode() + b"\x00"
            for field_type, field_value in fields
        )
        error_body += b"\x00"  # Final null byte terminates the message
        length = struct.pack("!I", len(error_body) + 4)

        self.write(b"E")
        self.write(length)
        self.write(error_body)
        await self.writer.drain()

    async def send_parameter_status(self, parameter, value):
        message = f"{parameter}\x00{value}\x00".encode()
        self.write(b"S")
        self.write(struct.pack("!I", len(message) + 4))
        self.write(message)
        await self.writer.drain()

    async def send_backend_key_data(self):
        self.write(b"K")
        self.session_secret_key = abs(
            struct.unpack("!I", secrets.token_bytes(4))[0]
        )
        self.write(struct.pack("!III", 12, self.pid, self.session_secret_key))
        await self.writer.drain()

    async def send_initial_parameters(self):
        # Sending a set of initial parameter status messages
        # TODO: Review these parameters
        parameters = {
            "server_version": "9.6.10",
            "server_encoding": "UTF8",
            "client_encoding": "UTF8",
            "application_name": "psql",
            "is_superuser": "off",
            "session_authorization": "postgres",
            "DateStyle": "ISO, DMY",
            "IntervalStyle": "postgres",
            "TimeZone": "UTC",
            "integer_datetimes": "on",
            "standard_conforming_strings": "on",
        }
        for param, value in parameters.items():
            await self.send_parameter_status(param, value)

    def set_parameter(self, set_item):
        # Set, EQ, Column, Identifier
        param = set_item.find(exp.Identifier)
        value = set_item.find(exp.Var)
        if value:
            is_string = False
            is_var = True
        else:
            value = set_item.find(exp.Literal)
            is_string = value.is_string
            is_var = False
        self.session_parameters[param] = SessionParameter(
            param.name,
            value.name,
            is_string=is_string,
            is_var=is_var,
            is_local=True,
        )

    async def execute_select(self, sql: str, params: List[any] = None):
        """Execute SQL Selects"""

        if params is None:
            params = []
        # TODO:
        # For each table in sql, query information in catalog, test if there are
        # access rules, transformations, virtual tables, etc. Retrieve the
        # connection information.
        #
        # Handle commands sent to a single source
        import asyncpg

        if True:
            import decimal

            pg_conf: Source = self.config.get_source("pg_test")

            conn = await asyncpg.connect(
                user=pg_conf.user,
                password=pg_conf.password,
                database=pg_conf.database,
                host=pg_conf.host,
                port=pg_conf.port,
            )
            for float_type in ["float4", "float8"]:
                await conn.set_type_codec(
                    float_type,
                    encoder=str,
                    decoder=decimal.Decimal,
                    schema="pg_catalog",
                    format="text",
                )
            try:
                if params:
                    log.info(
                        color(
                            f"Executing\n{sql}\nWith params: {repr(params)}",
                            fg="green",
                        )
                    )
                else:
                    log.info(f"\033[32mExecuting\n{sql}\033[m")
                stmt = await conn.prepare(sql)
                result = await stmt.fetch(*params)
                await self.send_pgsql_row_description(stmt)

                meta = stmt.get_attributes()
                count = 0

                for row in result:
                    buf = PgBuffer()
                    for col_inx, col in enumerate(row):
                        if self.binary_transfer:
                            value_bytes = self.value_to_bytes(
                                col, meta[col_inx].type.oid
                            )
                        else:
                            if col is None:
                                value_bytes = struct.pack("!i", -1)
                            elif isinstance(col, bool):
                                value_bytes = b"\x01" if col else b"\x00"
                            else:
                                value_bytes = str(col).encode()
                        buf.write_int32(len(value_bytes))
                        if isinstance(value_bytes, str):
                            buf.write_bytes(value_bytes.encode())
                        else:
                            buf.write_bytes(value_bytes)
                    data = buf.get_buffer()

                    self.write(b"D")
                    self.write(struct.pack("!ih", 6 + len(data), len(row)))
                    self.write(data)

                    count += 1
                    if self.canceling:
                        log.info("Canceling")
                        self.canceling = False
                        return
                await self.send_command_complete(f"SELECT {count}\x00".encode())
                await self.writer.drain()
            except asyncpg.exceptions.SyntaxOrAccessError as ut:
                await self.send_error(
                    severity=ut.severity,
                    code=ut.sqlstate,
                    message=ut.message,
                )
                return
            finally:
                await conn.close()

    async def send_pgsql_row_description(self, stmt):
        cols = stmt.get_attributes()
        data = pgsql.get_row_description(stmt)
        self.write(b"T")
        self.write(struct.pack("!ih", 6 + len(data), len(cols)))
        self.write(data)


# Main server handling
async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    args: argparse.Namespace,
    certificates: List[Path],
) -> None:
    with open(args.config) as f:
        config = Config.from_dict(yaml.load(f, Loader=yaml.Loader))
    catalog_type: str = config.catalog.type
    if catalog_type == "file":
        catalog = FileCatalog(config.catalog.path).build()
    else:
        catalog = None

    handler = AsyncPsqlHandler(
        reader, writer, args, config, certificates, catalog
    )
    await handler.handle()


async def main(args: argparse.Namespace) -> None:
    cur_dir = Path.cwd()

    certificates: List[Path] = [
        cur_dir / Path("./etc/certificate.crt"),
        cur_dir / Path("./etc/private.key"),
    ]
    server = await asyncio.start_server(
        lambda reader, writer: handle_client(reader, writer, args, certificates),
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
        choices=["plain", "md5", "scram-sha-256"],
    )
    parser.add_argument(
        "-c",
        "--config",
        required=False,
        default="config.yaml",
        help="Configuration file",
    )
    parser.add_argument(
        "--use-ssl",
        required=False,
        default=False,
        help="Use SSL",
        action="store_true",
    )
    args: argparse.Namespace = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("Server stopped")
