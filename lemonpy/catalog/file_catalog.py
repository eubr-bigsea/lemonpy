from typing import Any, Dict

import yaml

from lemonpy.custom_types import Catalog, Column, Database, Schema, Table


class FileCatalog:
    __slots__ = ("catalog", "path")

    def __init__(self, path: str):
        self.path = path

    def build(self):
        with open(self.path) as f:
            yaml_data: Dict[str, Any] = yaml.safe_load(f)

        catalogs: Dict = {}
        self._parse_catalogs(yaml_data, catalogs)
        return catalogs

    def _parse_catalogs(self, yaml_data, catalogs):
        for catalog_name, catalog_data in yaml_data["catalogs"].items():
            catalog = Catalog(
                name=catalog_name,
                source_name=catalog_data["source_name"],
            )
            self._parse_databases(catalog_data, catalog)
            catalogs[catalog_name] = catalog

    def _parse_databases(self, catalog_data, catalog):
        for db_name, db_data in catalog_data["databases"].items():
            database = Database(name=db_name)
            self._parse_schemas(db_data, database)
            catalog.databases[db_name] = database

    def _parse_schemas(self, db_data: Dict[str, Any], database: Database):
        for schema_name, schema_data in db_data["schemas"].items():
            schema = Schema(name=schema_name)
            relation_types: list[str] = ["tables", "views"]
            for rel_type in relation_types:
                if rel_type in schema_data:
                    self._parse_relations(schema_data, schema, rel_type)
            database.schemas[schema_name] = schema

    def _parse_relations(
        self, schema_data: Dict[str, Any], schema: Schema, rel_type: str
    ):
        for rel_name, rel_data in schema_data[rel_type].items():
            relation = Table(name=rel_name, view=rel_data.get("view"))
            if rel_data and "columns" in rel_data:
                self._parse_columns(rel_data, relation)
            getattr(schema, rel_type)[rel_name] = relation

    def _parse_columns(self, rel_data: Dict[str, Any], relation: Table):
        relation.columns = {}
        for col_name, col_data in rel_data["columns"].items():
            relation.columns[col_name] = Column(name=col_name, **col_data)
