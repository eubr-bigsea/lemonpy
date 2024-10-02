class BaseField:
    def __repr__(self) -> str:
        return str(self)

class IntField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 23  # Integer type ID in PostgreSQL
        self.type_size = 4  # Size of the integer in bytes
    def __str__(self):
        return 'Int'


class TextField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 25  # Text type ID in PostgreSQL
        self.type_size = -1  # Variable size
    def __str__(self):
        return 'Text'


class OIDField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 26  # OID type ID in PostgreSQL
        self.type_size = 4  # Size of OID is 4 bytes
    def __str__(self):
        return 'OID'


class CharField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 18  # Char type ID in PostgreSQL
        self.type_size = 1  # Single-byte char
    def __str__(self):
        return 'Char'


class SmallIntField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 21  # Smallint type ID in PostgreSQL
        self.type_size = 2  # Size of smallint is 2 bytes
    def __str__(self):
        return 'SmallInt'


class JSONField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 114  # JSON type ID in PostgreSQL
        self.type_size = -1  # Variable size
    def __str__(self):
        return 'JSON'


class XMLField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 142  # XML type ID in PostgreSQL
        self.type_size = -1  # Variable size
    def __str__(self):
        return 'XML'


class MoneyField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 790  # Money type ID in PostgreSQL
        self.type_size = 8  # Size of money is 8 bytes
    def __str__(self):
        return 'Money'


class DateArrayField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 1182  # Array of dates type ID in PostgreSQL
        self.type_size = -1  # Variable size
    def __str__(self):
        return 'DateArra'


class BitField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 1560  # Bit type ID in PostgreSQL
        self.type_size = -1  # Variable size
    def __str__(self):
        return 'Bit'


class NumericField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 1700  # Numeric type ID in PostgreSQL
        self.type_size = -1  # Variable size
    def __str__(self):
        return 'Numeric'


class Float4Field(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 700  # Real (float4) type ID in PostgreSQL
        self.type_size = 4  # Size of float4 is 4 bytes
    def __str__(self):
        return 'Float4'


class Float8Field(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 701  # Double precision (float8) type ID in PostgreSQL
        self.type_size = 8  # Size of float8 is 8 bytes
    def __str__(self):
        return 'Float8'


class BigIntField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 20  # Bigint type ID in PostgreSQL
        self.type_size = 8  # Size of bigint is 8 bytes
    def __str__(self):
        return 'BigInt'


class VarCharField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 1043  # Varchar type ID in PostgreSQL
        self.type_size = -1  # Variable size
    def __str__(self):
        return 'VarChar'


class IntArrayField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 1005  # Array of integers type ID in PostgreSQL
        self.type_size = -1  # Variable size
    def __str__(self):
        return 'IntArray'


class BoolField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 16  # Boolean type ID in PostgreSQL
        self.type_size = 1  # Size of boolean is 1 byte
    def __str__(self):
        return 'Bool'


class TimestampField(BaseField):
    def __init__(self, name):
        self.name = name
        self.type_id = 1114  # Timestamp without time zone type ID in PostgreSQL
        self.type_size = 8  # Size of timestamp is 8 bytes
    def __str__(self):
        return 'Timestamp'

def field_factory(name, type_id):
    field_map = {
        23: IntField,
        25: TextField,
        26: OIDField,
        18: CharField,
        21: SmallIntField,
        114: JSONField,
        142: XMLField,
        790: MoneyField,
        1182: DateArrayField,
        1560: BitField,
        1700: NumericField,
        700: Float4Field,
        701: Float8Field,
        20: BigIntField,
        1043: VarCharField,
        1005: IntArrayField,
        16: BoolField,
        1114: TimestampField
    }

    field_class = field_map.get(type_id)

    if field_class:
        return field_class(name)
    else:
        raise ValueError(f"Unsupported type_id: {type_id}")