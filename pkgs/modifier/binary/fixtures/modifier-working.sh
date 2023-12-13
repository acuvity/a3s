#!/bin/sh

while read -r line; do
	echo '{"token": {"identity": ["z=z"]}}'
done <"/dev/stdin"
