import pytest
from sqlglot import exp
from lemonpy.validation import validate_same_database, load_catalog, validate_table_in_catalog

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
'''
def test_validate_table_in_catalog_invalid_schema():

    tables = [
        exp.Table(this="iris", catalog="postgres", db="not_existent_schema"),  # Dont have scheme
    ]

    with pytest.raises(ValueError):
        validate_table_in_catalog(tables, catalog)

def test_validate_table_in_catalog_invalid_database():

    tables = [
        exp.Table(this="iris", catalog="not_existent_db", db="public"),  # Dont have DB
    ]

    with pytest.raises(ValueError):
        validate_table_in_catalog(tables, catalog)

def test_validate_table_in_catalog_valid_and_invalid_tables():
    tables = [

        exp.Table(this="iris", catalog="postgres", db="public"),
        exp.Table(this="not_existent_table", catalog="postgres", db="public"),  # Dont have table
    ]

    with pytest.raises(ValueError):
        validate_table_in_catalog(tables, catalog)
'''