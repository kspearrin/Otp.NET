@echo off
cd %~dp0

SETLOCAL

:build
call npm install -g gulp-cli
call npm install
call gulp
