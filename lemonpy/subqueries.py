from sqlglot import parse_one, exp
import sqlglot

import yaml
from typing import Dict

import yaml

def load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)


def transform_columns(expr: exp.Expression, catalog: dict, current_db: str, current_schema: str, roles: list[str]):
    for table in expr.find_all(exp.Table):
        db = table.catalog or current_db
        schema = table.db or current_schema
        table_name = table.this if isinstance(table.this, str) else table.this.name

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
                    
                    try:
                        #print(f"Aplicando WHERE para {col_name} com valor: {value}")

                        formatted_value = value.strip("()")

                        condition = parse_one(formatted_value)

                        current_where = expr.args.get("where")

                        if current_where:
                            new_where = exp.Where(
                                this=exp.And(this=current_where, expression=condition)
                            )
                        else:
                            new_where = exp.Where(this=condition)

                        expr.set("where", new_where)

                        #print("SQL Final com WHERE:", expr.sql())

                    except Exception as e:
                        raise ValueError(f"Failed to apply WHERE condition for column '{col_name}': {e}")


                #intervalo de valores ?? ou so uma string ?
                elif action == "BUCKETS":
                    try:
                        num_buckets = int(value)

                        #limites para o salary
                        min_salary = 1000
                        max_salary = 100000

                        bucket_size = (max_salary - min_salary) / num_buckets    #intervalo de cada bucket


                        case_conditions = []
                        for i in range(num_buckets):
                            lower_bound = min_salary + i * bucket_size
                            upper_bound = lower_bound + bucket_size

                            condition = f"WHEN {col_name} >= {lower_bound} AND {col_name} < {upper_bound} THEN 'Bucket {i + 1}'"
                            case_conditions.append(condition)

                        case_conditions.append(f"ELSE 'Out of range'")

                        case_expression = f"CASE {' '.join(case_conditions)} END"

                        bucket_expr = parse_one(case_expression)
                        column.replace(bucket_expr)

                    except Exception as e:
                        raise ValueError(f"Failed to apply BUCKETS action for column '{col_name}': {e}")


                elif action == "PROJECT":
                    try:
                        if "case" in value.lower():
                            if "when" not in value.lower():
                                value = value.lower().replace("case", "case when", 1)
        
                        formatted_value = value.replace("salary", col_name)

                        case_expr = parse_one(formatted_value)

                        column.replace(case_expr)

                    except Exception as e:
                        raise ValueError(f"Failed to apply PROJECT action for column '{col_name}': {e}")

                

                break

def transform_table(table: exp.Table, catalog: dict, current_db: str, current_schema: str, roles: list[str]) -> exp.Expression:
    db = table.catalog or current_db
    schema = table.db or current_schema  
    table_name = table.name

    # Verifica se o banco de dados existe no catálogo
    databases = catalog['catalogs']['default']['databases']
    if db not in databases:
        raise ValueError(f"Database '{db}' not found in catalog. Please connect to a valid database.")
    
    # Verifica se o esquema existe no banco de dados
    schemas = databases[db]['schemas']
    if not schemas:
        raise ValueError(f"No schemas found in database '{db}'.")

    table_data = None
    for schema_name, schema_data in schemas.items():
        if table_name in schema_data['tables']:
            table_data = schema_data['tables'][table_name]
            schema = schema_name  
            break

    if not table_data:
        raise ValueError(f"Table '{table_name}' not found in any schema of database '{db}'.")


    available_roles = table_data.get('roles', {})
    print(f"Roles disponíveis no catálogo: {list(available_roles.keys())}")

    invalid_roles = [role for role in roles if role not in available_roles]
    if invalid_roles:
        raise ValueError(f"Invalid roles detected: {invalid_roles}. Please check the user's permissions.")


    for role in roles:
        role_action = available_roles.get(role)
    
        if not role_action:
            continue  

        action = role_action.get('action')
        value = role_action.get('value')
        print(f"Ação: {action}, Valor: {value}")

        if action == "DENY":
            
            print(f"Access denied to table '{table_name}' for role '{role}'.")

            raise ValueError(f"Access to table '{table_name}' is denied for role '{role}'.")
        
        elif action == "WHERE":
            if "filter" in table_data:
                filter_condition = table_data["filter"]
                combined_filter = f"{filter_condition} AND {value}" if value else filter_condition
                return parse_one(f"(SELECT * FROM {db}.{schema}.{table_name} WHERE {combined_filter}) AS {table.alias_or_name}")
            else:
                return parse_one(f"(SELECT * FROM {db}.{schema}.{table_name} WHERE {value}) AS {table.alias_or_name}")

        elif action == "READER":
            return exp.Table(this=f"{db}.{schema}.{table_name}", alias=table.alias)

        elif action == "VIEW":
            if "view" in table_data:
                return parse_one(f"({table_data['view']}) AS {table.alias_or_name}")

    print(f"No applicable rule found for roles {roles}. Applying default logic.")

    if "filter" in table_data:
        filter_condition = table_data["filter"]
        return parse_one(f"(SELECT * FROM {db}.{schema}.{table_name} WHERE {filter_condition}) AS {table.alias_or_name}")

    if "view" in table_data:
        return parse_one(f"({table_data['view']}) AS {table.alias_or_name}")

    if "table" in table_data:
        renamed_table = table_data["table"]
        return exp.Table(this=renamed_table, alias=table.alias)

    return exp.Table(this=f"{db}.{schema}.{table_name}", alias=table.alias)



def replace_tables(expr: exp.Expression, catalog: dict, current_db: str, current_schema: str, roles: list[str]):
    for table in expr.find_all(exp.Table):
        transformed_table = transform_table(table, catalog, current_db, current_schema, roles)
        if transformed_table != table:
            table.replace(transformed_table)
            break
    transform_columns(expr, catalog, current_db, current_schema, roles)
