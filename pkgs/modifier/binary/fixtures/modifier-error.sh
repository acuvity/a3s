#!/bin/sh

while read -r line; do
	echo '{"error": "oh noes"}'
done <"/dev/stdin"
