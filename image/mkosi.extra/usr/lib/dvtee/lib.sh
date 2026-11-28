# Shared by `provision` and `start`. Sourced, not executed.
# shellcheck shell=bash disable=SC2034 # DVTEE_ARGS and DVTEE_LOG are outputs
#
# Everything here treats its input as hostile: the provisioning disk comes
# from the host, and the config it carries ends up on the sealed disk, where
# `start` reads it on every boot. Only a fixed set of files with fixed formats
# is accepted, and `start` turns them into flags itself. Nothing is sourced
# or passed through as environment, so the host cannot set, say,
# --insecure-http or --allow-deposits.

DVTEE_DATA=${DVTEE_DATA:-/var/lib/dvtee}

# Every path the provisioning archive may contain.
DVTEE_TAR_NAMES='^(validator_keys/?|config/?|validator_keys/keystore-[0-9]{1,5}\.(json|txt)|config/(network|config\.yaml|genesis-validators-root|tls-sans|knownClients\.txt|cluster-lock\.json|tokens\.txt|log-level))$'

dvtee_fail() {
	echo "dvtee: $*" >&2
	return 1
}

# Checks `tar -tvf` output ($1) and `tar -tf` output ($2): only regular files
# and directories, and only whitelisted names.
dvtee_check_listing() {
	local verbose=$1 names=$2 line n=0
	[[ -s $names ]] || { dvtee_fail "the provisioning archive is empty"; return 1; }
	while IFS= read -r line; do
		case ${line:0:1} in
		-|d) ;;
		*) dvtee_fail "provisioning archive: not a regular file or directory: $line"; return 1 ;;
		esac
		n=$((n + 1))
	done <"$verbose"
	while IFS= read -r line; do
		[[ $line =~ $DVTEE_TAR_NAMES ]] || { dvtee_fail "provisioning archive: unexpected entry '$line'"; return 1; }
		n=$((n - 1))
	done <"$names"
	((n == 0)) || { dvtee_fail "provisioning archive: listings disagree"; return 1; }
}

# One line of at most $3 bytes matching $2.
dvtee_check_line() {
	local f=$1 re=$2 max=$3 v
	[[ -f $f && ! -L $f ]] || { dvtee_fail "missing $f"; return 1; }
	(($(stat -c %s "$f") <= max)) || { dvtee_fail "$f is too large"; return 1; }
	(($(wc -l <"$f") <= 1)) || { dvtee_fail "$f must be one line"; return 1; }
	v=$(<"$f")
	[[ $v =~ $re ]] || { dvtee_fail "$f: invalid value"; return 1; }
}

# Printable text of at most $2 bytes.
dvtee_check_text() {
	local f=$1 max=$2
	[[ -f $f && ! -L $f ]] || { dvtee_fail "missing $f"; return 1; }
	(($(stat -c %s "$f") <= max)) || { dvtee_fail "$f is too large"; return 1; }
	! LC_ALL=C grep -q '[^[:print:][:space:]]' "$f" || { dvtee_fail "$f is not plain text"; return 1; }
}

# Validates a data dir layout ($1): config/ and validator_keys/.
dvtee_check_config() {
	local d=$1 c=$1/config k=$1/validator_keys net f n=0
	dvtee_check_line "$c/network" '^(mainnet|hoodi|sepolia|config\.yaml)$' 16 || return 1
	net=$(<"$c/network")
	if [[ $net == config.yaml ]]; then
		dvtee_check_text "$c/config.yaml" 65536 || return 1
		dvtee_check_line "$c/genesis-validators-root" '^0x[0-9a-fA-F]{64}$' 80 || return 1
	else
		[[ ! -e $c/config.yaml && ! -e $c/genesis-validators-root ]] \
			|| { dvtee_fail "config.yaml and genesis-validators-root are only for --network config.yaml"; return 1; }
	fi
	if [[ -e $c/tls-sans ]]; then
		dvtee_check_line "$c/tls-sans" '^[A-Za-z0-9.:-]+(,[A-Za-z0-9.:-]+)*$' 512 || return 1
	fi
	if [[ -e $c/knownClients.txt ]]; then
		dvtee_check_text "$c/knownClients.txt" 16384 || return 1
	fi
	# The signer checks both fully; these are size and type limits.
	if [[ -e $c/cluster-lock.json ]]; then
		dvtee_check_text "$c/cluster-lock.json" 67108864 || return 1
	fi
	if [[ -e $c/tokens.txt ]]; then
		dvtee_check_text "$c/tokens.txt" 16384 || return 1
	fi
	if [[ -e $c/log-level ]]; then
		dvtee_check_line "$c/log-level" '^(info|debug)$' 8 || return 1
	fi
	[[ -d $k && ! -L $k ]] || { dvtee_fail "missing $k"; return 1; }
	for f in "$k"/keystore-*.json; do
		[[ -f $f && ! -L $f ]] || continue
		[[ -f ${f%.json}.txt && ! -L ${f%.json}.txt ]] || { dvtee_fail "$f has no password file"; return 1; }
		n=$((n + 1))
	done
	((n > 0)) || { dvtee_fail "no keystores in $k"; return 1; }
}

# Fills DVTEE_ARGS with the `serve` flags for data dir $1.
dvtee_build_args() {
	local d=$1 c=$1/config net
	dvtee_check_config "$d" || return 1
	net=$(<"$c/network")
	DVTEE_ARGS=(
		serve
		--platform tee
		--data-dir "$d"
		--keystores-dir "$d/validator_keys"
		--listen 0.0.0.0:9000
		--public-listen 0.0.0.0:9001
	)
	if [[ $net == config.yaml ]]; then
		DVTEE_ARGS+=(--network "$c/config.yaml" --genesis-validators-root "$(<"$c/genesis-validators-root")")
	else
		DVTEE_ARGS+=(--network "$net")
	fi
	if [[ -e $c/tls-sans ]]; then
		DVTEE_ARGS+=(--tls-san "$(<"$c/tls-sans")")
	fi
	if [[ -e $c/knownClients.txt ]]; then
		DVTEE_ARGS+=(--tls-known-clients "$c/knownClients.txt")
	fi
	if [[ -e $c/cluster-lock.json ]]; then
		DVTEE_ARGS+=(--cluster-lock "$c/cluster-lock.json")
	fi
	if [[ -e $c/tokens.txt ]]; then
		DVTEE_ARGS+=(--auth-token-file "$c/tokens.txt")
	fi
	DVTEE_LOG=dvtee=info,tower_http=warn
	if [[ -e $c/log-level && $(<"$c/log-level") == debug ]]; then
		DVTEE_LOG=dvtee=debug,tower_http=info
	fi
}
