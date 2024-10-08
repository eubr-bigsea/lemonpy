# LemonPy
Exposes an interface based on the PGWire Protocol (PostgreSQL Protocol) that
allow query data. An internal catalog defines rules for accessing, transforming,
anonymizing and audinging data.

## Installing

## Configuring

## Using
You can use any tool with PostgreSQL support, for example, `psql` command or
DBeaver tool. Also, you can use programming languages, such as Python and Java,
with their respective PostgreSQL drivers.

Many commands are not implemented, specially those used for changing data (
`INSERT`, `DELETE`, `UPDATE`, etc) or DML (data manipulation language) commands
(CREATE/ALTER/DROP). Most part of the ANSI SQL SELECT is supported.

Inter-catalog queries are not supported (yet).

## To generate certificates
    openssl genrsa -out private.key 2048
    openssl req -new -key private.key -out request.csr
    openssl x509 -req -days 365 -in request.csr -signkey private.key -out certificate.crt