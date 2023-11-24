MAKEFLAGS += --warn-undefined-variables

plugin:
	go build -buildmode=plugin -trimpath

plugin_linux:
	GOOS=linux GOARCH=amd64 go build -buildmode=plugin -trimpath
