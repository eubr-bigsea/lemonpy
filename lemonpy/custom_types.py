from dataclasses import dataclass, field
from typing import List, Any, Dict, Union


@dataclass
class Source:
    host: str
    user: str
    password: str
    database: str
    port: int

    @classmethod
    def from_dict(cls, data):
        return cls(**data)


# -----------------------------


@dataclass
class Rule:
    action: str
    value: Union[str, int, float]


@dataclass
class Role:
    name: str
    rule: Rule


@dataclass
class Column:
    name: str
    roles: List[Role]

class Duration:
    ...

@dataclass
class CacheControl:
    control_type: str
    periodicity: Duration
    ttl: Duration
    parameters: List[str]

@dataclass
class Table:
    name: str
    view: str
    cache_control: CacheControl
    columns: List[Column]


@dataclass
class Schema:
    name: str
    tables: List[Table]


@dataclass
class Database:
    name: str
    schemas: List[Schema]


@dataclass
class Catalog:
    name: str
    source_name: str
    databases: List[Database]


@dataclass
class Config:
    sources: Dict[str, Source]
    catalogs: Dict[str, Catalog]

    @classmethod
    def from_dict(cls, data) -> None:
        return cls(
            sources=dict(
                [
                    (k, Source.from_dict(v))
                    for (k, v) in data.get("sources", []).items()
                ]
            ),
            catalogs={}
        )

    def get_source(self, name: str) -> Source:
        return self.sources.get(name)


# --------------------------------
@dataclass
class PreparedStatement:
    name: str
    query: str
    parameter_types: List[int] = field(default_factory=list)


@dataclass
class Portal:
    name: str
    statement_name: str
    parameters: List[Any] = field(default_factory=list)
    result_format: List[int] = field(default_factory=list)


@dataclass
class SessionParameter:
    name: str
    value: str
    is_local: bool = False
    is_string: bool = False
    is_var: bool = False

    def __repr__(self) -> str:
        return f"{self.name=} {self.value=} {self.is_local=} {self.is_string=} {self.is_var=}"
