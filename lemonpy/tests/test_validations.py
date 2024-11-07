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

# Tests para validar se as tabelas estão no mesmo banco de dados
def test_validate_same_database_with_postgres_tables():
    tables = [
        Table(this=Identifier(this="iris"), catalog="postgres"),
        Table(this=Identifier(this="titanic"), catalog="postgres")
    ]
    validate_same_database(tables, "postgres")  # Deve passar sem exceções

def test_validate_same_database_with_mixed_databases():
    tables = [
        Table(this=Identifier(this="iris"), catalog="postgres"),
        Table(this=Identifier(this="lixo"), catalog="example")
    ]
    with pytest.raises(ValueError):
        validate_same_database(tables, "postgres")  # Deve lançar ValueError

# Tests para validate_table_in_catalog
def test_validate_table_in_catalog_with_existing_table():
    tables = [
        Table(this=Identifier(this="iris"), catalog="postgres", db="public")
    ]
    validate_table_in_catalog(tables, catalog, "postgres", "public")  # Deve passar sem exceções

def test_validate_table_in_catalog_with_nonexistent_table():
    tables = [
        Table(this=Identifier(this="unknown_table"), catalog="postgres", db="public")
    ]
    with pytest.raises(ValueError):
        validate_table_in_catalog(tables, catalog, "postgres", "public")  # Deve lançar ValueError
'''
# Tests para validate_columns_in_catalog
def test_validate_columns_in_catalog_with_existing_column():
    # Consulta com uma coluna existente na tabela
    expr = exp.select(Column(this=Identifier(this="sepallength"))).from_("postgres.public.iris")
    validate_columns_in_catalog(expr, catalog, "postgres", "public")  # Deve passar sem exceções

def test_validate_columns_in_catalog_with_nonexistent_column():
    # Consulta com uma coluna inexistente deve gerar erro
    expr = exp.select(Column(this=Identifier(this="nonexistent_column"))).from_("postgres.public.iris")
    with pytest.raises(ValueError):
        validate_columns_in_catalog(expr, catalog, "postgres", "public")  # Deve lançar ValueError
'''