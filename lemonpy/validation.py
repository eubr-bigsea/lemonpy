import sqlglot
from sqlglot.expressions import Table
from typing import List, Dict
from gettext import gettext
import yaml

def load_catalog(catalog_path: str = "catalog.yaml") -> Dict:

    with open(catalog_path, 'r') as file:
        return yaml.safe_load(file)

# Notice: in sqlglot, catalog = database and db = schema
def validate_same_database(tables: List[Table], current_db: str) -> None:
    #initialization, with empty values
    databases = set() #Here set is used to store all the databases(catalogs) of the referenced tables, as sets do not allow duplicate values.

    for table in tables:
        #iterates through each table in the tables list and gets the database(catalog)
        db = table.catalog 
        databases.add(db)

    if len(databases) > 1:
        raise ValueError(gettext("Queries between different databases ({}) are not allowed.").format(', '.join(databases)))

# Notice: in sqlglot, catalog = database and db = schema
def validate_table_in_catalog(tables: List[Table], catalog: Dict, current_db: str, current_schema: str) -> None:
    
    for table in tables:
        
        db = table.catalog
        schema = table.db 
        table_name = table.name

        if db not in catalog or schema not in catalog[db]['schemas'] or table_name not in catalog[db]['schemas'][schema]['tables']:
            raise ValueError(gettext("Table {} is not in the catalog in database {}, schema {}").format(table_name, db, schema))


def validate_columns_in_catalog(expr, catalog: Dict, current_db: str, current_schema: str) -> None:
   
    for table in sqlglot.get_all(expr, Table):
        
        db = table.catalog or current_db
        schema = table.db or current_schema
        table_name = table.name

        catalog_columns = catalog[db]['schemas'][schema]['tables'][table_name]['columns']

        for column in sqlglot.get_columns(expr):
            
            if column not in catalog_columns:
                #raise ValueError(f"Column {column} does not exist in table {table_name}.")
                raise ValueError(gettext("Column {} does not exist in table {}").format(column, table_name))

#validações de usuarios, permições