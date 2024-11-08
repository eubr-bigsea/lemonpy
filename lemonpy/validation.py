import sqlglot
from sqlglot.expressions import Table
from sqlglot import expressions as exp
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

        if  table_name not in catalog['catalogs']['default']['databases'][db]['schemas'][schema]['tables']:
            raise ValueError(gettext("Table {} is not in the catalog in database {}, schema {}").format(table_name, db, schema))

def validate_columns_in_catalog(expr, catalog: Dict, current_db: str, current_schema: str) -> None:

    for table in expr.find_all(exp.Table):

        db = table.catalog or current_db
        schema = table.db or current_schema
        table_name = table.name

        catalog_columns = catalog['catalogs']['default']['databases'][db]['schemas'][schema]['tables'][table_name]['columns']

        for column in expr.find_all(exp.Column):
            
            column_name = column.name  
            if column_name not in catalog_columns:
                raise ValueError(gettext("Column {} does not exist in table {}").format(column_name, table_name))
            
#validações de usuarios, permições