#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

: "${TYPESAFE_API_KEY:?Set TYPESAFE_API_KEY to a key from https://console.typesafe.ai/}"

for project in . examples/demo; do
    if [[ ! -x "$project/venv/bin/python" ]]; then
        uv venv "$project/venv"
    fi
    uv pip install --python "$project/venv/bin/python" -r "$project/requirements.txt"
done

cd examples/demo
mkdir -p .pulumi
export PULUMI_BACKEND_URL="file://$PWD/.pulumi"
export PULUMI_CONFIG_PASSPHRASE=demo
unset PULUMI_API PULUMI_ACCESS_TOKEN AWS_PROFILE AWS_SESSION_TOKEN
export AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
pulumi stack select dev --create --non-interactive
exec pulumi preview --policy-pack ../.. --non-interactive
