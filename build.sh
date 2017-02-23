#!/bin/bash -e

rm -f *.html
rm -rf resources

while getopts "r" opt; do
    case "$opt" in
    r)
        REBUILD=1
        ;;
    esac
done

if [ $REBUILD ]; then 
    rm -f KeycloakWebBuilder.jar
fi

if [ ! -f KeycloakWebBuilder.jar ]; then
    mvn -f src/web-builder/pom.xml package
    cp src/web-builder/target/KeycloakWebBuilder-1.0-SNAPSHOT.jar KeycloakWebBuilder.jar
fi

java -jar KeycloakWebBuilder.jar
