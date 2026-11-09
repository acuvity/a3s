#!/bin/sh

# Answers each token with its own identity plus m=m, so a caller can tell its
# answer from another's. A token with identity "slow=slow" is answered after
# 1.5s, later than the modifier waits.
while read -r line; do
	case "$line" in
	*'"slow=slow"'*) sleep 1.5 ;;
	esac
	echo "$line" | sed -E 's/.*"identity":\[([^]]*)\].*/{"token": {"identity": [\1, "m=m"]}}/'
done <"/dev/stdin"
