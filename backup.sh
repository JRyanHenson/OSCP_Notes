#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

rsync -a --delete /home/kali/Notes/CheatSheets/ ./CheatSheets/
rsync -a --delete /home/kali//Notes/C-ProvingGroundNotes/ ./C-ProvingGroundNotes/
rsync -a --delete /home/kali/Notes/Tools/ ./Tools/

if ! git diff --quiet; then
  git add .
  git commit -m "Daily backup $(date +%F)"
  git push
fi
