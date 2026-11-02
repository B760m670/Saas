#!/bin/sh
# Сборка движка эффектов в один файл: site/fx/energy.js, и метка версии в
# кабинете (FX_SRC в site/index.html) — по ней браузер понимает, что файл
# сменился, и не берёт старый из кеша.
#
# Нужен только при правке исходников в src/ — собранный файл лежит в
# репозитории, и сервер его не собирает.
#   npm i --no-save three@0.169.0 esbuild@0.24.0 && sh build.sh
set -eu
cd "$(dirname "$0")"
npx esbuild src/index.js --bundle --minify --format=iife --target=es2019 \
  --legal-comments=none --outfile=energy.js
v=$(sha256sum energy.js | cut -c1-10)
sed -i "s#fx/energy.js?v=[A-Za-z0-9_]*#fx/energy.js?v=$v#" ../index.html
echo "energy.js v=$v"
