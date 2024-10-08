import re
from lemonpy.pg_buffer import PgBuffer


def get_row_description(stmt):
    type_length = {
        16: 1,  # bool
        21: 2,  # int2
        23: 4,  # int4
        20: 8,  # int8
        700: 4,  # float4
        701: 8,  # float8
        1082: 4,  # date
        1114: 8,  # timestamp (without time zone)
        1184: 8,  # timestamptz (with time zone)
        1083: 8,  # time (without time zone)
        1266: 8,  # timetz (with time zone)
        2950: 16,  # uuid
        1186: 16,  # interval
        1560: 6,  # bit
        18: 1,  # char (single character)
        19: 64,  # name
        22: 6,  # int2vector
        26: 4,  # oid
        600: 24,  # point
        601: 32,  # lseg
        602: 48,  # path
        718: 8,  # circle
        869: 32,  # inet
        651: 16,  # macaddr
    }

    buf = PgBuffer()
    cols = stmt.get_attributes()

    for i, col in enumerate(cols):
        buf.write_string(col.name.encode("utf-8"))
        buf.write_int32(0)  # Table ID
        buf.write_int16(i + 1)  # Column index
        buf.write_int32(col.type.oid)
        buf.write_int16(type_length.get(col.type.oid, -1))  # Column length
        buf.write_int32(-1)  # Type modifier
        buf.write_int16(0)  # Text format code

    return buf.get_buffer()
