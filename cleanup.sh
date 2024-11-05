#!/usr/bin/env bash

rm -f enmass3_output.* masscan* nrich*
rm -f ./log/*
if [[ -d "./log" && -z "$(ls -A ./log)" ]]; then
    rmdir ./log
fi
