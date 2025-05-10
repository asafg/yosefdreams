#!/bin/bash

echo 'curl -X POST "http://localhost:8080/api/auth/signup" \' >&2
echo '    -H "Content-Type: application/json" \' >&2
echo "    -d '{\"username\": \"admin\",\"email\": \"admin@gmail.com\",  \"password\": \"admin\"}'" >&2
curl -X POST "http://localhost:8080/api/auth/signup" \
     -H "Content-Type: application/json" \
     -d '{"username": "admin","email": "admin@gmail.com",  "password": "admin"}'

echo -e '\n'
