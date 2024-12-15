from sqlglot import parse_one, exp

import yaml
from typing import Dict

import yaml

def load_config(config_path: str = "config.yaml") -> dict:
    with open(config_path, 'r') as file:
        return yaml.safe_load(file)
'''
def load_config(config_path: str = "config.yaml") -> Dict:
    with open(config_path, 'r') as file:
      return yaml.safe_load(file)
'''
'''
def transform_columns(expr: exp.Expression, catalog: dict, current_db: str, current_schema: str, roles: list[str]):
   
    for table in expr.find_all(exp.Table):
        db = table.catalog or current_db
        schema = table.db or current_schema
        #table_name = table.name
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
                
               #elif action == "ANONYMIZE":
                
                break
'''

'''
def transform_columns(expr: exp.Expression, catalog: dict, current_db: str, current_schema: str, roles: list[str]):
    """
    Modifica as colunas da expressão SQL com base nas permissões e transformações definidas no catálogo.
    """
    # Iterar sobre tabelas na consulta
    for table in expr.find_all(exp.Table):
        db = table.catalog or current_db
        schema = table.db or current_schema
        table_name = table.this if isinstance(table.this, str) else table.this.name

        # Obter definições da tabela e colunas do catálogo
        table_data = catalog['catalogs']['default']['databases'][db]['schemas'][schema]['tables'].get(table_name, {})
        columns = table_data.get('columns', {})

        # Iterar sobre colunas na consulta
        for column in expr.find_all(exp.Column):
            col_name = column.name
            col_data = columns.get(col_name)

            if not col_data:
                continue  # Nenhuma definição específica para esta coluna no catálogo

            # Verificar as permissões para os roles atribuídos ao usuário
            for role in roles:
                role_action = col_data.get('roles', {}).get(role)
                if not role_action:
                    continue  # Nenhuma ação definida para este role

                action = role_action.get('action')
                value = role_action.get('value')

                # Aplicar a transformação com base na ação definida
                if action == "DENY":
                    # Negar acesso à coluna
                    raise ValueError(f"Access denied to column {col_name} for role {role}.")

                elif action == "WHERE":
                    # Adicionar uma cláusula WHERE para filtrar valores
                    where_condition = exp.condition(value)
                    expr.set("where", exp.and_(expr.args.get("where"), where_condition))

                elif action == "BUCKETS":
                    # Substituir coluna por buckets (ex: faixas de valores)
                    bucket_expr = exp.Case(
                        conditions=[
                            exp.When(
                                this=exp.LT(
                                    this=exp.Column(this=col_name),
                                    expression=exp.Literal(this=value)
                                ),
                                then=exp.Literal(this="Bucket 1")
                            )
                        ],
                        default=exp.Literal(this=f"Bucket {value}")
                    )
                    column.replace(bucket_expr)

                elif action == "PROJECT":
                    # Projetar valores calculados com base em uma expressão definida
                    projection_expr = parse_one(value.replace("salary", col_name))
                    column.replace(projection_expr)

                elif action == "ANONYMIZE":
                    # Anonimizar coluna com um valor fixo ou máscara
                    anonymized_expr = exp.Literal(this=value)
                    column.replace(anonymized_expr)

                break  # Processar apenas o primeiro role correspondente
'''
    
'''
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
        #verificar novamente no catalogo, ta errado
        return parse_one(f"({cache_query}) AS {table.alias_or_name}")

    if "filter" in table_data:
        #trocar a implementação
        filter_condition = table_data["filter"]
        return parse_one(f"(SELECT * FROM {db}.{schema}.{table_name} WHERE {filter_condition}) AS {table.alias_or_name}")
        #logica errada
    if "bucket" in table_data:
        bucket_rules = table_data["bucket"]
        #pegar as colunas em outro look, talvez
        bucket_query = f"SELECT {', '.join([f'{rule} AS {col}' for col, rule in bucket_rules.items()])} FROM {db}.{schema}.{table_name}"
        return parse_one(f"({bucket_query}) AS {table.alias_or_name}")

    return table
'''
'''
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
                        filter_expr = parse_one(value)  # Verifica a validade da expressão diretamente
                    except Exception as e:
                        raise ValueError(f"Invalid WHERE condition in catalog for column '{col_name}': {value}. Error: {e}")

                    current_where = expr.args.get("where")

                    if current_where:
                        new_where = exp.And(this=current_where, expression=filter_expr)
                    else:
                        new_where = filter_expr

                    expr.set("where", new_where)





                elif action == "BUCKETS":
                    bucket_expr = exp.Case(
                        conditions=[
                            exp.When(
                                this=exp.LT(
                                    this=exp.Column(this=col_name),
                                    expression=exp.Literal(this=value)
                                ),
                                then=exp.Literal(this="Bucket 1")
                            )
                        ],
                        default=exp.Literal(this=f"Bucket {value}")
                    )
                    column.replace(bucket_expr)

                elif action == "PROJECT":
                    projection_expr = parse_one(value.replace("salary", col_name))
                    column.replace(projection_expr)

                elif action == "ANONYMIZE":
                    anonymized_expr = exp.Literal(this=value)
                    column.replace(anonymized_expr)

                break  
'''
from sqlglot import parse_one, exp

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

                        print(f"Formatted value before parsing: {formatted_value}")

                        case_expr = parse_one(formatted_value)

                        print(f"Parsed case expression: {case_expr.sql()}")

                        column.replace(case_expr)

                    except Exception as e:
                        raise ValueError(f"Failed to apply PROJECT action for column '{col_name}': {e}")

                

                break  


def transform_table(table: exp.Table, catalog: dict, current_db: str, current_schema: str) -> exp.Expression:

    db = table.catalog or current_db
    schema = table.db or current_schema  
    table_name = table.name

    databases = catalog['catalogs']['default']['databases']
    
    if db not in databases:
        raise ValueError(f"Database '{db}' not found in catalog. Please connect to a valid database.")
    
    schemas = databases[db]['schemas']

    if not schemas:
        raise ValueError(f"No schemas found in database '{db}'.")
    
    table_found = False
    for schema_name, schema_data in schemas.items():
        if table_name in schema_data['tables']:
            table_found = True
            table_data = schema_data['tables'][table_name]
            schema = schema_name  
            break
    
    if not table_found:
        raise ValueError(f"Table '{table_name}' not found in any schema of database '{db}'.")

    if "view" in table_data:
        return parse_one(f"({table_data['view']}) AS {table.alias_or_name}")

    if "table" in table_data:
        renamed_table = table_data["table"]
        return exp.Table(this=renamed_table, alias=table.alias)

    if "filter" in table_data:
        filter_condition = table_data["filter"]
        return parse_one(f"(SELECT * FROM {db}.{schema}.{table_name} WHERE {filter_condition}) AS {table.alias_or_name}")

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