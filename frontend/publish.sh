#!/bin/bash
set -v

pushd build
echo "pc.cro.sh" > CNAME
git init
git remote add origin https://github.com/cr0sh/pc.cro.sh-deploy.git
git add .
git commit -a -m "Deployment at $(date +%Y-%m-%d-%H-%M-%S)"
git push --force origin master