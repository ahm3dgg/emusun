rem sunshuttle was built as a win32 gui app, that explains why you won't see it pop a console.

@echo off
go build -ldflags="-H windowsgui" .
