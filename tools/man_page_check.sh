#!/usr/bin/env bash

click-man cve &> /dev/null && git diff --quiet man/ &> /dev/null
