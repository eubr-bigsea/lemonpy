import pytest
from sqlglot import exp
from sqlglot.expressions import Table, Identifier
from lemonpy.validation import validate_same_database, load_catalog, validate_table_in_catalog, validate_columns_in_catalog

catalog = load_catalog("../catalog.yaml")  
#tests tables and catalogs
def test_validate_same_database_with_postgres_tables():

    tables = [
        exp.Table(this="iris", catalog="postgres"),
        exp.Table(this="titanic", catalog="postgres")
    ]

    validate_same_database(tables, "postgres") # NOT throw ValueError, should pass without exceptions, same catalog(database)

def test_validate_same_database_with_mixed_databases():

    tables = [
        exp.Table(this="iris", catalog="postgres"),
        exp.Table(this="lixo", catalog="test")
    ]

    with pytest.raises(ValueError):
        validate_same_database(tables, "postgres") # Must throw a ValueError, because its diferent catalog(database)

def test_validate_table_in_catalog_with_existing_table():

    tables = [
        Table(this=Identifier(this="iris"), catalog="postgres", db="public")
    ]

    validate_table_in_catalog(tables, catalog, "postgres", "public") 

def test_validate_table_in_catalog_with_nonexistent_table():

    tables = [
        Table(this=Identifier(this="lixo_table"), catalog="postgres", db="public")
    ]

    with pytest.raises(ValueError):
        validate_table_in_catalog(tables, catalog, "postgres", "public")  

def test_validate_columns_in_catalog_with_multiple_columns():

    expr = exp.select("sepallength", "class").from_("postgres.public.iris")
    validate_columns_in_catalog(expr, catalog, "postgres", "public")

def test_validate_columns_in_catalog_with_nonexistent_column():

    expr = exp.select("lixo_column").from_("postgres.public.iris")

    with pytest.raises(ValueError):
        validate_columns_in_catalog(expr, catalog, "postgres", "public")  