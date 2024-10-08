from sqlglot.expressions import Set, Insert, Select, Delete, Expression
import sqlglot
from typing import List

import sqlglot.optimizer
import sqlglot.schema


def get_ast(sql: str, dialect: str) -> List[Expression]:
    return sqlglot.parse(sql=sql, dialect=dialect)


def optimize(expr: Expression, **kwargs) -> Expression:
    from sqlglot.optimizer import Optimizer

    # Create an Optimizer instance with a specific optimization disabled
    optimizer = Optimizer(disable=["optimization_name"])
    return sqlglot.optimizer.optimize(expr, optimizer=optimizer, **kwargs)


def get_all(ast: Expression, type: Expression) -> Expression:
    root = sqlglot.optimizer.build_scope(ast)
    return [
        source
        for scope in root.traverse()
        for alias, (node, source) in scope.selected_sources.items()
        if isinstance(source, type)
    ]


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
