#!/usr/bin/env bash

# Usage: update_dependencies.sh <module-path> <local-checkout-name>
# Pins a dependency to the current HEAD of a sibling checkout.

PROJECTS=$(dirname "$0")/../..
go get -x "$1"@$(git -C "$PROJECTS/$2" rev-parse HEAD)
go mod tidy
