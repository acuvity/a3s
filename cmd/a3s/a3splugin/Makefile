MAKEFLAGS += --warn-undefined-variables

plugin:
	go build -buildmode=plugin

plugin_linux:
	GOOS=linux GOARCH=amd64 go build -buildmode=plugin
