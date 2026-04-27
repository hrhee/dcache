#!/bin/sh
#
# Generates TLS certificates for ZooKeeper and the dCache Curator client.
# These are DISPOSABLE TEST CERTIFICATES only. Do NOT use in production.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# CA
openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem -subj "/CN=ZooKeeper-Test-CA"

# ZooKeeper server keystore
keytool -genkeypair -alias zookeeper -keyalg RSA -keysize 2048 \
    -dname "CN=localhost" -keystore zookeeper-keystore.p12 \
    -storetype PKCS12 -storepass password -keypass password -validity 3650

keytool -certreq -alias zookeeper -keystore zookeeper-keystore.p12 \
    -storetype PKCS12 -storepass password -file zookeeper.csr

openssl x509 -req -days 3650 -in zookeeper.csr \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out zookeeper-cert.pem

keytool -importcert -alias ca -file ca-cert.pem \
    -keystore zookeeper-keystore.p12 -storetype PKCS12 -storepass password -noprompt

keytool -importcert -alias zookeeper -file zookeeper-cert.pem \
    -keystore zookeeper-keystore.p12 -storetype PKCS12 -storepass password

keytool -importcert -alias ca -file ca-cert.pem \
    -keystore zookeeper-truststore.p12 -storetype PKCS12 -storepass password -noprompt

# Curator client keystore
keytool -genkeypair -alias curator -keyalg RSA -keysize 2048 \
    -dname "CN=dcache-client" -keystore curator-keystore.p12 \
    -storetype PKCS12 -storepass password -keypass password -validity 3650

keytool -certreq -alias curator -keystore curator-keystore.p12 \
    -storetype PKCS12 -storepass password -file curator.csr

openssl x509 -req -days 3650 -in curator.csr \
    -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out curator-cert.pem

keytool -importcert -alias ca -file ca-cert.pem \
    -keystore curator-keystore.p12 -storetype PKCS12 -storepass password -noprompt

keytool -importcert -alias curator -file curator-cert.pem \
    -keystore curator-keystore.p12 -storetype PKCS12 -storepass password

keytool -importcert -alias ca -file ca-cert.pem \
    -keystore curator-truststore.p12 -storetype PKCS12 -storepass password -noprompt
