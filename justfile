binary := "mailscraper"

set windows-shell := ["cmd.exe", "/c"]

default:
    @just --list

build:
    go build -o {{ binary }} .

test:
    go test -v -coverprofile coverage.out ./...

cover: test
    go tool cover -html coverage.out

clean:
    {{ if os() == "windows" { "@if exist " + binary + " del " + binary + "\n    @if exist coverage.out del coverage.out" } else { "rm -f " + binary + " coverage.out" } }}

run *args: build
    {{ if os() == "windows" { "" } else { "./" } }}{{ binary }} {{ args }}
