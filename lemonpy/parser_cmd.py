from sqlglot.expressions import Set, Insert, Select, Delete, Expression
import sqlglot
from typing import List


def get_ast(sql: str) -> List[Expression]:
    return sqlglot.parse(sql=sql)


def describe(parsed_query: Expression, catalog: any):
    if not isinstance(parsed_query, Select):
        raise ValueError("Not supported")
    result = []

    # Extract all tables with aliases
    table_aliases = {
        t.alias_or_name: t.name for t in parsed_query.find_all(sqlglot.exp.Table)
    }

    # Extract columns in the SELECT clause
    columns = parsed_query.find_all(sqlglot.exp.Column)

    for column in columns:
        table_alias = column.table
        column_name = column.name

        # Match table alias to the actual table name
        if table_alias in table_aliases:
            table_name = table_aliases[table_alias]
        else:
            raise ValueError(f"Unknown table alias '{table_alias}'.")

        # Validate and describe each column
        if column_name in catalog[table_name]["columns"]:
            column_type = catalog[table_name]["types"][column_name]
            result.append((f"{table_alias}.{column_name}", column_type))
        else:
            raise ValueError(
                f"Column '{column_name}' does not exist in table '{table_name}'."
            )

    return result
