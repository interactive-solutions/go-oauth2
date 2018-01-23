#!/usr/bin/env bash

echo "Running go test..."
go test github.com/interactive-solutions/go-oauth2/...

echo "Running go vet..."
go vet github.com/interactive-solutions/go-oauth2/...
