#!/bin/bash
if [ $# -ne 5 ] || [ $4 != "NO" ]; then
  open /Applications/Google\ Chrome.app/ index.html --args --disable-web-security --allow-file-access-from-files
fi
python main.py -u $1 -p $2 -l "$3"
