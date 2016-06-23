#!/bin/bash

DIR=`dirname $0`/src/web

while true; do 
    inotifywait -r -e modify,attrib,close_write,move,create,delete $DIR/config.json $DIR/news $DIR/pages $DIR/resources $DIR/templates $DIR/versions && ./build.sh
done
