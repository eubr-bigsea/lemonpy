from pathlib import Path
import argparse
import asyncio
import hashlib
import logging
import random
import re
import secrets
import ssl
import struct
from gettext import gettext
from typing import Dict, List

import sqlglot.expressions as exp
import yaml
from pg_buffer import PgBuffer
from pg_data_types import IntField, VarCharField, field_factory
from sqlglot import Expression, errors

import lemonpy.backends.postgresql as pgsql
from lemonpy.custom_types import (
    Config,
    Portal,
    PreparedStatement,
    SessionParameter,
    Source,
)
from lemonpy.parser_cmd import get_ast

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
        "canceling",
        "client_encoding",
        "config",
        "current_database",
        "pgbuf",
        "pid",
        "prepared_statements",
        "portals",
        "reader",
        "session_parameters",
        "session_secret_key",
        "settings",
        "user",
        "waiting_describe",
        "writer",
        "certificates",
    )

    def __init__(self, reader, writer, args, config, certificates):
        self.config = config
        self.reader = reader
        self.writer = writer
        self.pgbuf = PgBuffer(reader, writer)
        self.args = args
        self.settings = {}  # Store settings (command SET)
        self.waiting_describe = None
        self.prepared_statements: Dict[str, PreparedStatement] = {}
        self.portals: Dict[str, Portal] = {}
        self.session_parameters: Dict[str, SessionParameter] = {}
        self.canceling = False
        self.session_secret_key = None
        self.pid = random.randint(1000, 64000)
        self.current_database = None
        self.client_encoding = "UTF8"
        self.application_name = None
        self.user = None
        self.certificates = certificates

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

            breakpoint()
            await self.send_ssl_response()
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

    async def handle_bind(self):
        # Read message length
        _ = await self.pgbuf.read_int32()

        # Read portal name and prepared statement name (both are null-terminated)
        portal_name = await self.read_null_terminated_string()
        statement_name = await self.read_null_terminated_string()
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
            await self.send_row_description(
                fields
            )  # Modify based on your schema
        elif desc_type == b"P":
            # Describe a portal
            print(desc_name)
            portal = self.portals.get(desc_name)
            if not portal:
                raise Exception(f"Portal {desc_name} not found.")

            # Send RowDescription message for the portal
            await self.send_row_description(
                fields
            )  # Modify based on your schema

        # Send Describe Complete
        await self.send_describe_complete()

    async def send_describe_complete(self):
        self.write(struct.pack("!ci", b"3", 4))  # '3' for DescribeComplete
        await self.writer.drain()

    async def handle_set_command(self, match):
        self.settings[match.group(2)] = [
            match.group(1) is not None
            and "LOCAL" == match.group(1).strip().upper(),
            match.group(3),
        ]
        print(f"Executing SET command: {self.settings}")

        # Send CommandComplete message
        await self.send_command_complete("SET\x00".encode())

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
        portal = self.prepared_statements.get(portal_name)

        sql = portal.query.strip("\0")  # Assuming portal contains the query
        match = set_command_regex.match(sql)

        # print("=" * 20)
        # print(self.prepared_statements)
        # print(portal)
        # print('>>>', sql, match)
        # print("=" * 20)

        # FIXME Implement execute
        if match:
            # Handle SET command
            await self.handle_set_command(match)
        elif sql.strip() == "SELECT current_schema(),session_user":
            # FIXME Handle common queries
            rows = [["public", "postgres"]]
            if self.waiting_describe:
                await self.handle_describe(
                    [
                        VarCharField("current_schema"),
                        VarCharField("session_user"),
                    ]
                )

            # 2. Send actual rows
            await self.send_row_data(rows)
            # 3. Send command complete with a valid completion tag, e.g., "SELECT n"
            await self.send_command_complete(
                f"SELECT {len(rows)}\x00".encode()
            )  # Indicates 3 rows returned

        else:
            if self.waiting_describe:
                await self.handle_describe()
            print(f"Executing portal {portal_name}, max_rows: {max_rows}")
            # Execute the query associated with the portal
            # For now, this is a mock implementation
            # You should replace this with actual query execution based on the portal
            rows = [[1, 2], [3, 4], [5, 6]] if max_rows == 0 else [[1, 2]]

            # Send RowData for the rows
            await self.send_row_data(rows)

            # Send CommandComplete message
            await self.send_command_complete("SELECT\x00".encode())

        self.waiting_describe = False
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
            parameter_types.append(field_factory("", param_type))

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

        expr: Expression = None
        try:
            expr_list: List[Expression] = get_ast(sql)
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
                return await self.execute_select(sql)
            elif isinstance(expr, exp.Set):
                for set_item in expr.find_all(exp.SetItem):
                    self.set_parameter(set_item)
                    print("=" * 20)
                    for v in self.session_parameters.values():
                        print(v)
                    print("=" * 20)
                await self.send_command_complete(b"SET\x00")
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
        msglen = await self.pgbuf.read_int32()
        version = await self.pgbuf.read_int32()
        v_maj = version >> 16
        v_min = version & 0xFFFF

        msg = await self.pgbuf.read_parameters(msglen - 8)
        for i in range(len(msg), 2):
            if msg[i] == b"user":
                self.user = msg[i + 1].decode()
            elif msg[i] == b"database":
                self.current_database = msg[i + 1].decode()
            elif msg[i] == b"application_name":
                self.application_name = msg[i + 1].decode()
            elif msg[i] == b"client_encoding":
                self.client_encoding = msg[i + 1].decode()

        log.info(f"Client PSQL {v_maj}.{v_min} - {msg}")

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
            self.handle_ssl_connection()

    async def handle_ssl_connection(self):
        """Transforma a conexão em segura e inicia a lógica do protocolo pgwire."""
        # Cria um novo socket seguro a partir do socket original
        ssl_socket = await self._secure_socket(self.writer)
        secure_reader = asyncio.StreamReader(ssl_socket)
        secure_writer = asyncio.StreamWriter(
            ssl_socket, None, self.writer.transport
        )

        await self.handle_pgwire_protocol(secure_reader, secure_writer)

    async def _secure_socket(self, writer):
        """Promove o socket original para SSL."""
        # Promove a conexão original para SSL
        ssl_transport = writer.transport
        ssl_socket = ssl_transport.get_extra_info("socket")

        # Inicia a negociação SSL no socket
        ssl_socket = ssl.wrap_socket(
            ssl_socket,
            server_side=True,
            certfile=self.certificates[0],
            keyfile=self.certificates[1],
        )
        return ssl_socket

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

    # async def send_row_description(self, fields):
    #     buf = PgBuffer()
    #     for field in fields:
    #         buf.write_string(field.name)
    #         buf.write_int32(0)  # Table ID
    #         buf.write_int16(0)  # Column ID
    #         buf.write_int32(field.type_id)
    #         buf.write_int16(field.type_size)
    #         buf.write_int32(-1)  # Type modifier
    #         buf.write_int16(0)  # Text format code
    #     data = buf.get_buffer()

    #     self.write(b"T")
    #     self.write(struct.pack("!ih", 6 + len(data), len(fields)))
    #     self.write(data)
    #     await self.writer.drain()

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

    async def execute_select(self, sql: str):
        """Execute SQL Selects"""

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
                stmt = await conn.prepare(sql)
                result = await stmt.fetch()
                await self.send_pgsql_row_description(stmt)
                count = 0

                for row in result:
                    buf = PgBuffer()
                    for col in row:
                        # print(col, str(col), type(col))
                        v = str(col).encode()
                        buf.write_int32(len(v))
                        buf.write_bytes(v)
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
async def handle_client(reader, writer, args, certificates):
    with open(args.config) as f:
        config = Config.from_dict(yaml.load(f, Loader=yaml.Loader))
    handler = AsyncPsqlHandler(reader, writer, args, config, certificates)
    await handler.handle()


async def main(args):
    # To generate certificates
    # openssl genrsa -out private.key 2048
    # openssl req -new -key private.key -out request.csr
    # openssl x509 -req -days 365 -in request.csr -signkey private.key -out certificate.crt
    if args.use_ssl:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        cur_dir = Path.cwd()
        ssl_context.load_cert_chain(
            certfile=cur_dir / Path("./etc/certificate.crt"),
            keyfile=cur_dir / Path("./etc/private.key"),
        )
    else:
        ssl_context = None
    certificates = [
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
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        print("Server stopped")
