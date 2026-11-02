#!/bin/sh
# Сборка движка эффектов в один файл: site/fx/energy.js.
# Нужен только при правке исходников в src/ — собранный файл лежит в
# репозитории, и сервер его не собирает.
#   npm i --no-save three@0.169.0 esbuild@0.24.0 && sh build.sh
set -eu
cd "$(dirname "$0")"
npx esbuild src/index.js --bundle --minify --format=iife --target=es2019 \
  --legal-comments=none --outfile=energy.js
ls -l energy.js
