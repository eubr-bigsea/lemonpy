import pytest
import asyncio
import sqlglot
import yaml
from pathlib import Path
import argparse
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Any, Dict, List
from server import AsyncPsqlHandler, Config, FileCatalog
from pg_buffer import PgBuffer
from custom_types import (
    Config,
    Portal,
    PreparedStatement,
    SessionParameter,
    Source,
)

reader = asyncio.StreamReader()
writer = AsyncMock() 


cur_dir = Path.cwd()
certificates: List[Path] = [
    cur_dir / Path("./etc/certificate.crt"),
    cur_dir / Path("./etc/private.key"),
]


with open('config.yaml') as f:
    config = Config.from_dict(yaml.load(f, Loader=yaml.Loader))


catalog_type: str = config.catalog.type
if catalog_type == "file":
    catalog = FileCatalog(config.catalog.path).build()
else:
    catalog = None
args = argparse.Namespace(bind='localhost', port=5432, auth='plain', config='config.yaml', use_ssl=False)

handler = AsyncPsqlHandler(reader, writer, args, config=config, certificates=certificates, catalog=catalog)

@pytest.mark.asyncio
async def test_cancel_request():
    pg_buffer = PgBuffer()
    
    pg_buffer.write_int32(8) 
    pg_buffer.write_int32(80877102)  
    
    reader.feed_data(pg_buffer.get_buffer())

    result = await handler.read_ssl_or_cancel_request()

    print(result)
    assert result is True  

@pytest.mark.asyncio
async def test_authentication():
    pg_buffer = PgBuffer()
    pg_buffer.write_bytes(b'p' +  b'\x00\x00\x00\x0a' + b'sp33d')
    reader.feed_data(pg_buffer.get_buffer())

    result = await handler.read_()
    assert result is True

@pytest.mark.asyncio
async def test_authentication_failure():
    pg_buffer = PgBuffer()
    pg_buffer.write_bytes(b'p' +  b'\x00\x00\x00\x0a' + b'fakepassword')
    reader.feed_data(pg_buffer.get_buffer())

    result = await handler.read_()
    assert result is False

@pytest.mark.asyncio
async def test_delete_query():
    query = 'DELETE FROM public.iris;'
    await handler._handle_query(query)
    with patch.object(AsyncPsqlHandler, 'send_error', new_callable=AsyncMock):
        await handler._handle_query(query)
        handler.send_error.assert_awaited_once_with(
        severity="FATAL",
        code="28P01",
        message="Command of type 'Delete' not supported"
        )

@pytest.mark.asyncio
async def test_select_query():
    query = 'SELECT * FROM public.iris;'
    with patch.object(AsyncPsqlHandler, 'execute_select', new_callable=AsyncMock):
        handler.current_database = 'iris'
        await handler._handle_query(query)
        handler.execute_select.assert_awaited() 

@pytest.mark.asyncio
async def test_set_query():
    query = "SET timezone TO 'UTC';"
    with patch.object(AsyncPsqlHandler, 'send_command_complete', new_callable=AsyncMock):
        handler.current_database = 'iris'
        await handler._handle_query(query)
        handler.send_command_complete.assert_awaited_once_with(b"SET\x00")

@pytest.mark.asyncio
async def test_parse():
    pg_buffer = PgBuffer()
    pg_buffer.clear_buffer()
    pg_buffer.write_string('name')
    pg_buffer.write_string('select * from public.iris;')
    pg_buffer.write_int16(3)
    pg_buffer.write_int32(1)
    pg_buffer.write_int32(2)
    pg_buffer.write_int32(3)
    reader.feed_data(pg_buffer.get_buffer())
    result = await handler.handle_parse()
    assert str(handler.prepared_statements['name']) == str(PreparedStatement(name='name', query='select * from public.iris;', parameter_types=[1, 2, 3]))


@pytest.mark.asyncio
async def test_bind():
    with patch.object(AsyncPsqlHandler, 'send_bind_complete', new_callable=AsyncMock):
        pg_buffer = PgBuffer()
        pg_buffer.clear_buffer()
        pg_buffer.write_int32(60)
        # pg_buffer.write_int16(1)
        pg_buffer.write_string('portal_name')
        pg_buffer.write_string('statement_name')
        pg_buffer.write_int16(1)
        pg_buffer.write_int16(4)
        pg_buffer.write_int16(2)
        pg_buffer.write_int32(2)
        pg_buffer.write_string('p1')
        pg_buffer.write_int32(2)
        pg_buffer.write_string('p2')
        pg_buffer.write_int16(1)
        pg_buffer.write_int16(5)
        reader.feed_data(pg_buffer.get_buffer())
        result = await handler.handle_bind()
        handler.send_bind_complete.assert_awaited() 

@pytest.mark.asyncio
async def test_execute_not_in_portals():
  with patch.object(AsyncPsqlHandler, 'send_error', new_callable=AsyncMock):
        pg_buffer = PgBuffer()
        pg_buffer.clear_buffer()
        pg_buffer.write_int32(70)
        pg_buffer.write_string('portal_name')
        pg_buffer.write_int32(4)
        reader.feed_data(pg_buffer.get_buffer())
        await handler.handle_execute()
        await handler.send_error.assert_awaited_once_with(
                "FATAL", "XX000", f"Portal {'portal_name'} not found."
            )


@pytest.mark.asyncio
async def test_close():
    with patch.object(AsyncPsqlHandler, 'send_close_complete', new_callable=AsyncMock):
        pg_buffer = PgBuffer()
        pg_buffer.clear_buffer()
        pg_buffer.write_int32(30)
        pg_buffer.write_string('P')
        pg_buffer.write_int32(3)
        reader.feed_data(pg_buffer.get_buffer())
        await handler.handle_close()
        handler.send_close_complete.assert_awaited() 
        