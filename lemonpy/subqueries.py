import sqlglot
from sqlglot import parse_one, exp


def replace_locations(expr):

    for table in expr.find_all(exp.Table):

        if table.name == "locations":

            subquery = parse_one(
                "(SELECT * FROM postgres.company.fake_locations) AS locations"
            )

            table.replace(subquery)
