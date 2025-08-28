#!/bin/sh
set -e
export VAULT_ADDR=${VAULT_ADDR:-http://vault:8200}
export VAULT_TOKEN=${VAULT_TOKEN:-root}
tries=0
until curl -s $VAULT_ADDR/v1/sys/health | grep -q '"initialized":true'; do
  tries=$((tries+1))
  if [ $tries -gt 60 ]; then
    echo "Vault not ready"; exit 1
  fi
  sleep 1
done
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -X POST $VAULT_ADDR/v1/sys/mounts/transit -d '{"type":"transit"}' || true
curl -s -H "X-Vault-Token: $VAULT_TOKEN" -X POST $VAULT_ADDR/v1/transit/keys/sek -d '{"type":"aes256-gcm96"}' || true
echo "Vault transit key 'sek' ready"
