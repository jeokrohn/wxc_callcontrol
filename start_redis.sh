#!/usr/bin/env bash
# start a local redis instance
docker run --name redis -d -v "${PWD}":/data -p 6379:6379 redis:alpine --save 60 1