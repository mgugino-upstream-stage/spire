#!/bin/bash

podman run --name my-cassandra -d \
	--network host --memory=2g \
	--replace \
        -v $(pwd)/cassandra2.yaml:/etc/cassandra/cassandra.yaml:Z \
	-e MAX_HEAP_SIZE=1G -e HEAP_NEWSIZE=256M \
	cassandra:latest

        #-v $(pwd)/cassandra.yaml:/etc/cassandra/cassandra.yaml:ro,Z \
