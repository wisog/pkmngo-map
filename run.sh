#!/bin/bash
open /Applications/Google\ Chrome.app/ index.html --args --disable-web-security --allow-file-access-from-files
python main.py -u $1 -p $2 -l "$3"
