from sqlglot import parse_one, exp
import yaml
from typing import Dict

def load_config(config_path: str = "config.yaml") -> Dict:
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)
    
def transform_columns(expr: exp.Expression, catalog: dict, current_db: str, current_schema: str, roles: list[str]):
   
    for table in expr.find_all(exp.Table):
        db = table.catalog or current_db
        schema = table.db or current_schema
        table_name = table.name

        table_data = catalog['catalogs']['default']['databases'][db]['schemas'][schema]['tables'].get(table_name, {})
        columns = table_data.get('columns', {})

        for column in expr.find_all(exp.Column):
            col_name = column.name
            col_data = columns.get(col_name)

            if not col_data:
                continue  

            for role in roles:
                role_action = col_data.get('roles', {}).get(role)
                if not role_action:
                    continue  

                action = role_action.get('action')
                value = role_action.get('value')

                if action == "DENY":
                    raise ValueError(f"Access denied to column {col_name} for role {role}.")

                elif action == "WHERE":
                    where_condition = exp.Condition(
                        this=exp.Literal(this=value)  
                    )
                    expr = exp.Select(
                        expressions=expr.expressions,
                        where=where_condition
                    )

                elif action == "BUCKETS":
                    bucket_query = f"CASE WHEN {col_name} < {value} THEN 'Bucket 1' ELSE 'Bucket {value}' END AS {col_name}"
                    column.replace(exp.Literal(this=bucket_query))

                elif action == "PROJECT":
                    projection_query = value.replace("salary", col_name)
                    column.replace(exp.Literal(this=projection_query))
                '''
                elif action == "ANONYMIZE":
                    column.replace(exp.Literal(this=value))'''

                break

    

def transform_table(table: exp.Table, catalog: dict, current_db: str, current_schema: str) -> exp.Expression:
   
    db = table.catalog or current_db
    schema = table.db or current_schema
    table_name = table.name

    table_data = None
    schemas = catalog['catalogs']['default']['databases'][db]['schemas']
    
    if schema in schemas and table_name in schemas[schema]['tables']:
        table_data = schemas[schema]['tables'][table_name]
    else:
        for other_schema, schema_data in schemas.items():
            if table_name in schema_data['tables']:
                schema = other_schema
                table_data = schema_data['tables'][table_name]
                break
    
    if table_data is None:
        raise ValueError(f"Table {table_name} not found in any schema in database {db}.")

    if "view" in table_data:
        return parse_one(f"({table_data['view']}) AS {table.alias_or_name}")

    if "table" in table_data:
        renamed_table = table_data["table"]
        return exp.Table(this=renamed_table, alias=table.alias)

    if "cache" in table_data:
        cache_query = table_data["cache"]["validity_test"]
        return parse_one(f"({cache_query}) AS {table.alias_or_name}")

    if "filter" in table_data:
        filter_condition = table_data["filter"]
        return parse_one(f"(SELECT * FROM {db}.{schema}.{table_name} WHERE {filter_condition}) AS {table.alias_or_name}")

    if "bucket" in table_data:
        bucket_rules = table_data["bucket"]
        bucket_query = f"SELECT {', '.join([f'{rule} AS {col}' for col, rule in bucket_rules.items()])} FROM {db}.{schema}.{table_name}"
        return parse_one(f"({bucket_query}) AS {table.alias_or_name}")

    return table

def replace_tables(expr: exp.Expression, catalog: dict, current_db: str, current_schema: str, roles: list[str]):
    
    for table in expr.find_all(exp.Table):
        transformed_table = transform_table(table, catalog, current_db, current_schema)
        if transformed_table != table:
            table.replace(transformed_table)
            break
    transform_columns(expr, catalog, current_db, current_schema, roles)
#maybe do the same for columns, like transform_columns

#check this cases
'''
group1:
    action: PROJECT
    value: (case salary > 10000 then 'rich' else 'poor' end)
group2:
    action: ANONYMIZE
    value: []
'''