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
    type: str
    size: int = -1
    roles: List[Role] = field(default_factory=list)


class Duration: ...


@dataclass
class CacheControl:
    control_type: str
    periodicity: Duration
    ttl: Duration
    parameters: List[str]


class Relation:
    pass


@dataclass
class Table(Relation):
    name: str
    view: str
    cache_control: CacheControl = None
    columns: Dict[str, Column] = field(default_factory=dict)


@dataclass
class Schema:
    name: str
    tables: Dict[str, Table] = field(default_factory=dict)
    views: Dict[str, Table] = field(default_factory=dict)


@dataclass
class Database:
    name: str
    schemas: Dict[str, Schema] = field(default_factory=dict)


@dataclass
class Catalog:
    name: str
    source_name: str
    databases: Dict[str, Database] = field(default_factory=dict)

    def d(self, name: str) -> Database:
        return self.databases.get(name)

@dataclass
class CatalogInfo:
    type: str
    path: str

@dataclass
class Config:
    sources: Dict[str, Source]
    catalog: CatalogInfo

    @classmethod
    def from_dict(cls, data) -> None:
        return cls(
            sources=dict(
                [
                    (k, Source.from_dict(v))
                    for (k, v) in data.get("sources", []).items()
                ]
            ),
            catalog=CatalogInfo(**data.get("catalog")),
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
