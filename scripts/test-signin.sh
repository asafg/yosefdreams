#!/bin/bash

echo 'curl -X POST "http://localhost:8080/api/auth/signin" \' >&2
echo '    -H "Content-Type: application/json" \' >&2
echo "    -d '{\"usernameOrEmail\": \"admin@gmail.com\", \"password\": \"admin\"}'" >&2

curl -X POST "http://localhost:8080/api/auth/signin" \
     -H "Content-Type: application/json" \
     -d '{"usernameOrEmail": "admin@gmail.com", "password": "admin"}'

echo -e '\n'
