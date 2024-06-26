#!/bin/sh

# Test various options that are not covered by compat.sh
#
# Here the goal is not to cover every ciphersuite/version, but
# rather specific options (max fragment length, truncated hmac, etc)
# or procedures (session resumption from cache or ticket, renego, etc).
#
# Assumes all options are compiled in.

set -u

# default values, can be overriden by the environment
: ${P_SRV:=../programs/ssl/ssl_server2}
: ${P_CLI:=../programs/ssl/ssl_client2}
: ${OPENSSL_CMD:=openssl} # OPENSSL would conflict with the build system
: ${GNUTLS_CLI:=gnutls-cli}
: ${GNUTLS_SERV:=gnutls-serv}
: ${PERL:=perl}

O_SRV="$OPENSSL_CMD s_server -www -cert data_files/server5.crt -key data_files/server5.key -dhparam data_files/dhparams.pem"
O_CLI="echo 'GET / HTTP/1.0' | $OPENSSL_CMD s_client"
G_SRV="$GNUTLS_SERV --x509certfile data_files/server5.crt --x509keyfile data_files/server5.key"
G_CLI="echo 'GET / HTTP/1.0' | $GNUTLS_CLI --x509cafile data_files/test-ca_cat12.crt"
TCP_CLIENT="$PERL scripts/tcp_client.pl"

TESTS=0
FAILS=0
SKIPS=0

CONFIG_H='../include/polarssl/config.h'

MEMCHECK=0
FILTER='.*'
EXCLUDE='^$'

print_usage() {
    echo "Usage: $0 [options]"
    printf "  -h|--help\tPrint this help.\n"
    printf "  -m|--memcheck\tCheck memory leaks and errors.\n"
    printf "  -f|--filter\tOnly matching tests are executed (default: '$FILTER')\n"
    printf "  -e|--exclude\tMatching tests are excluded (default: '$EXCLUDE')\n"
}

get_options() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -f|--filter)
                shift; FILTER=$1
                ;;
            -e|--exclude)
                shift; EXCLUDE=$1
                ;;
            -m|--memcheck)
                MEMCHECK=1
                ;;
            -h|--help)
                print_usage
                exit 0
                ;;
            *)
                echo "Unknown argument: '$1'"
                print_usage
                exit 1
                ;;
        esac
        shift
    done
}

# skip next test if the flag is not enabled in config.h
requires_config_enabled() {
    if grep "^#define $1" $CONFIG_H > /dev/null; then :; else
        SKIP_NEXT="YES"
    fi
}

# skip next test if the flag is enabled in config.h
requires_config_disabled() {
    if grep "^#define $1" $CONFIG_H > /dev/null; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if OpenSSL can't send SSLv2 ClientHello
requires_openssl_with_sslv2() {
    if [ -z "${OPENSSL_HAS_SSL2:-}" ]; then
        if $OPENSSL_CMD ciphers -ssl2 >/dev/null 2>&1; then
            OPENSSL_HAS_SSL2="YES"
        else
            OPENSSL_HAS_SSL2="NO"
        fi
    fi
    if [ "$OPENSSL_HAS_SSL2" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if OpenSSL doesn't support FALLBACK_SCSV
requires_openssl_with_fallback_scsv() {
    if [ -z "${OPENSSL_HAS_FBSCSV:-}" ]; then
        if $OPENSSL_CMD s_client -help 2>&1 | grep fallback_scsv >/dev/null
        then
            OPENSSL_HAS_FBSCSV="YES"
        else
            OPENSSL_HAS_FBSCSV="NO"
        fi
    fi
    if [ "$OPENSSL_HAS_FBSCSV" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# skip next test if GnuTLS isn't available
requires_gnutls() {
    if [ -z "${GNUTLS_AVAILABLE:-}" ]; then
        if ( which "$GNUTLS_CLI" && which "$GNUTLS_SERV" ) >/dev/null; then
            GNUTLS_AVAILABLE="YES"
        else
            GNUTLS_AVAILABLE="NO"
        fi
    fi
    if [ "$GNUTLS_AVAILABLE" = "NO" ]; then
        SKIP_NEXT="YES"
    fi
}

# print_name <name>
print_name() {
    printf "$1 "
    LEN=$(( 72 - `echo "$1" | wc -c` ))
    for i in `seq 1 $LEN`; do printf '.'; done
    printf ' '

    TESTS=$(( $TESTS + 1 ))
}

# fail <message>
fail() {
    echo "FAIL"
    echo "  ! $1"

    mv $SRV_OUT o-srv-${TESTS}.log
    mv $CLI_OUT o-cli-${TESTS}.log
    echo "  ! outputs saved to o-srv-${TESTS}.log and o-cli-${TESTS}.log"

    if [ "X${USER:-}" = Xbuildbot -o "X${LOGNAME:-}" = Xbuildbot ]; then
        echo "  ! server output:"
        cat o-srv-${TESTS}.log
        echo "  ! ============================================================"
        echo "  ! client output:"
        cat o-cli-${TESTS}.log
    fi

    FAILS=$(( $FAILS + 1 ))
}

# is_polar <cmd_line>
is_polar() {
    echo "$1" | grep 'ssl_server2\|ssl_client2' > /dev/null
}

# has_mem_err <log_file_name>
has_mem_err() {
    if ( grep -F 'All heap blocks were freed -- no leaks are possible' "$1" &&
         grep -F 'ERROR SUMMARY: 0 errors from 0 contexts' "$1" ) > /dev/null
    then
        return 1 # false: does not have errors
    else
        return 0 # true: has errors
    fi
}

# Wait for process $2 to be listening on port $1
if type lsof >/dev/null 2>/dev/null; then
    wait_server_start() {
        START_TIME=$(date +%s)
        while ! lsof -a -n -b -i "TCP:$1" -p "$2" >/dev/null 2>/dev/null; do
              if [ $(( $(date +%s) - $START_TIME )) -gt $DOG_DELAY ]; then
                  echo "SERVERSTART TIMEOUT"
                  echo "SERVERSTART TIMEOUT" >> $SRV_OUT
                  break
              fi
              # Linux and *BSD support decimal arguments to sleep. On other
              # OSes this may be a tight loop.
              sleep 0.1 2>/dev/null || true
        done
    }
else
    echo "Warning: lsof not available, wait_server_start = sleep $START_DELAY"
    wait_server_start() {
        sleep "$START_DELAY"
    }
fi

# wait for client to terminate and set CLI_EXIT
# must be called right after starting the client
wait_client_done() {
    CLI_PID=$!

    ( sleep "$DOG_DELAY"; echo "TIMEOUT" >> $CLI_OUT; kill $CLI_PID ) &
    WATCHDOG_PID=$!

    wait $CLI_PID
    CLI_EXIT=$?

    kill $WATCHDOG_PID
    wait $WATCHDOG_PID

    echo "EXIT: $CLI_EXIT" >> $CLI_OUT
}

# Usage: run_test name srv_cmd cli_cmd cli_exit [option [...]]
# Options:  -s pattern  pattern that must be present in server output
#           -c pattern  pattern that must be present in client output
#           -u pattern  lines after pattern must be unique in client output
#           -S pattern  pattern that must be absent in server output
#           -C pattern  pattern that must be absent in client output
#           -U pattern  lines after pattern must be unique in server output
run_test() {
    NAME="$1"
    SRV_CMD="$2"
    CLI_CMD="$3"
    CLI_EXPECT="$4"
    shift 4

    if echo "$NAME" | grep "$FILTER" | grep -v "$EXCLUDE" >/dev/null; then :
    else
        SKIP_NEXT="NO"
        return
    fi

    print_name "$NAME"

    # should we skip?
    if [ "X$SKIP_NEXT" = "XYES" ]; then
        SKIP_NEXT="NO"
        echo "SKIP"
        SKIPS=$(( $SKIPS + 1 ))
        return
    fi

    # prepend valgrind to our commands if active
    if [ "$MEMCHECK" -gt 0 ]; then
        if is_polar "$SRV_CMD"; then
            SRV_CMD="valgrind --leak-check=full $SRV_CMD"
        fi
        if is_polar "$CLI_CMD"; then
            CLI_CMD="valgrind --leak-check=full $CLI_CMD"
        fi
    fi

    # run the commands
    echo "$SRV_CMD" > $SRV_OUT
    $SRV_CMD >> $SRV_OUT 2>&1 &
    SRV_PID=$!
    wait_server_start "$PORT" "$SRV_PID"

    echo "$CLI_CMD" > $CLI_OUT
    eval "$CLI_CMD" >> $CLI_OUT 2>&1 &
    wait_client_done

    # kill the server
    kill $SRV_PID
    wait $SRV_PID

    # check if the client and server went at least to the handshake stage
    # (useful to avoid tests with only negative assertions and non-zero
    # expected client exit to incorrectly succeed in case of catastrophic
    # failure)
    if is_polar "$SRV_CMD"; then
        if grep "Performing the SSL/TLS handshake" $SRV_OUT >/dev/null; then :;
        else
            fail "server or client failed to reach handshake stage"
            return
        fi
    fi
    if is_polar "$CLI_CMD"; then
        if grep "Performing the SSL/TLS handshake" $CLI_OUT >/dev/null; then :;
        else
            fail "server or client failed to reach handshake stage"
            return
        fi
    fi

    # check server exit code
    if [ $? != 0 ]; then
        fail "server fail"
        return
    fi

    # check client exit code
    if [ \( "$CLI_EXPECT" = 0 -a "$CLI_EXIT" != 0 \) -o \
         \( "$CLI_EXPECT" != 0 -a "$CLI_EXIT" = 0 \) ]
    then
        fail "bad client exit code"
        return
    fi

    # check other assertions
    # lines beginning with == are added by valgrind, ignore them
    while [ $# -gt 0 ]
    do
        case $1 in
            "-s")
                if grep -v '^==' $SRV_OUT | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then :; else
                    fail "pattern '$2' MUST be present in the Server output"
                    return
                fi
                ;;

            "-c")
                if grep -v '^==' $CLI_OUT | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then :; else
                    fail "pattern '$2' MUST be present in the Client output"
                    return
                fi
                ;;

            "-S")
                if grep -v '^==' $SRV_OUT | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then
                    fail "pattern '$2' MUST NOT be present in the Server output"
                    return
                fi
                ;;

            "-C")
                if grep -v '^==' $CLI_OUT | grep -v 'Serious error when reading debug info' | grep "$2" >/dev/null; then
                    fail "pattern '$2' MUST NOT be present in the Client output"
                    return
                fi
                ;;

                # The filtering in the following two options (-u and -U) do the following
                #   - ignore valgrind output
                #   - filter out everything but lines right after the pattern occurances
                #   - keep one of each non-unique line
                #   - count how many lines remain
                # A line with '--' will remain in the result from previous outputs, so the number of lines in the result will be 1
                # if there were no duplicates.
            "-U")
                if [ $(grep -v '^==' $SRV_OUT | grep -v 'Serious error when reading debug info' | grep -A1 "$2" | grep -v "$2" | sort | uniq -d | wc -l) -gt 1 ]; then
                    fail "lines following pattern '$2' must be unique in Server output"
                    return
                fi
                ;;

            "-u")
                if [ $(grep -v '^==' $CLI_OUT | grep -v 'Serious error when reading debug info' | grep -A1 "$2" | grep -v "$2" | sort | uniq -d | wc -l) -gt 1 ]; then
                    fail "lines following pattern '$2' must be unique in Client output"
                    return
                fi
                ;;

            *)
                echo "Unknown test: $1" >&2
                exit 1
        esac
        shift 2
    done

    # check valgrind's results
    if [ "$MEMCHECK" -gt 0 ]; then
        if is_polar "$SRV_CMD" && has_mem_err $SRV_OUT; then
            fail "Server has memory errors"
            return
        fi
        if is_polar "$CLI_CMD" && has_mem_err $CLI_OUT; then
            fail "Client has memory errors"
            return
        fi
    fi

    # if we're here, everything is ok
    echo "PASS"
    rm -f $SRV_OUT $CLI_OUT
}

cleanup() {
    rm -f $CLI_OUT $SRV_OUT $SESSION
    kill $SRV_PID >/dev/null 2>&1
    kill $WATCHDOG_PID >/dev/null 2>&1
    exit 1
}

#
# MAIN
#

if cd $( dirname $0 ); then :; else
    echo "cd $( dirname $0 ) failed" >&2
    exit 1
fi

get_options "$@"

# sanity checks, avoid an avalanche of errors
if [ ! -x "$P_SRV" ]; then
    echo "Command '$P_SRV' is not an executable file"
    exit 1
fi
if [ ! -x "$P_CLI" ]; then
    echo "Command '$P_CLI' is not an executable file"
    exit 1
fi
if which $OPENSSL_CMD >/dev/null 2>&1; then :; else
    echo "Command '$OPENSSL_CMD' not found"
    exit 1
fi

# used by watchdog
MAIN_PID="$$"

# We use somewhat arbitrary delays for tests:
# - how long do we wait for the server to start (when lsof not available)?
# - how long do we allow for the client to finish?
#   (not to check performance, just to avoid waiting indefinitely)
# Things are slower with valgrind, so give extra time here.
#
# Note: without lsof, there is a trade-off between the running time of this
# script and the risk of spurious errors because we didn't wait long enough.
# The watchdog delay on the other hand doesn't affect normal running time of
# the script, only the case where a client or server gets stuck.
if [ "$MEMCHECK" -gt 0 ]; then
    START_DELAY=6
    DOG_DELAY=60
else
    START_DELAY=2
    DOG_DELAY=20
fi

# Pick a "unique" port in the range 10000-19999.
PORT="0000$$"
PORT="1$( printf $PORT | tail -c 4 )"

# fix commands to use this port
P_SRV="$P_SRV server_port=$PORT"
P_CLI="$P_CLI server_port=$PORT"
O_SRV="$O_SRV -accept $PORT"
O_CLI="$O_CLI -connect localhost:$PORT"
G_SRV="$G_SRV -p $PORT"
G_CLI="$G_CLI -p $PORT localhost"

# Also pick a unique name for intermediate files
SRV_OUT="srv_out.$$"
CLI_OUT="cli_out.$$"
SESSION="session.$$"

SKIP_NEXT="NO"

trap cleanup INT TERM HUP

# Basic test

# Checks that:
# - things work with all ciphersuites active (used with config-full in all.sh)
# - the expected (highest security) parameters are selected
#   ("signature_algorithm ext: 6" means SHA-512 (highest common hash))
run_test    "Default" \
            "$P_SRV debug_level=3" \
            "$P_CLI" \
            0 \
            -s "Protocol is TLSv1.2" \
            -s "Ciphersuite is TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384" \
            -s "client hello v3, signature_algorithm ext: 6" \
            -s "ECDHE curve: secp521r1" \
            -S "error" \
            -C "error"

# Test for uniqueness of IVs in AEAD ciphersuites
run_test    "Unique IV in GCM" \
            "$P_SRV exchanges=20 debug_level=4" \
            "$P_CLI exchanges=20 debug_level=4 force_ciphersuite=TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384" \
            0 \
            -u "IV used" \
            -U "IV used"

# Tests for rc4 option

run_test    "RC4: server disabled, client enabled" \
            "$P_SRV" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            1 \
            -s "SSL - None of the common ciphersuites is usable"

run_test    "RC4: server enabled, client disabled" \
            "$P_SRV force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            "$P_CLI" \
            1 \
            -s "SSL - The server has no ciphersuites in common"

run_test    "RC4: both enabled" \
            "$P_SRV arc4=1" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            0 \
            -S "SSL - None of the common ciphersuites is usable" \
            -S "SSL - The server has no ciphersuites in common"

# Test for SSLv2 ClientHello

requires_openssl_with_sslv2
run_test    "SSLv2 ClientHello: reference" \
            "$P_SRV debug_level=3" \
            "$O_CLI -no_ssl2" \
            0 \
            -S "parse client hello v2" \
            -S "ssl_handshake returned"

# Adding a SSL2-only suite makes OpenSSL client send SSLv2 ClientHello
requires_openssl_with_sslv2
run_test    "SSLv2 ClientHello: actual test" \
            "$P_SRV debug_level=2" \
            "$O_CLI -cipher 'DES-CBC-MD5:ALL'" \
            0 \
            -s "parse client hello v2" \
            -S "ssl_handshake returned"

# Tests for Truncated HMAC extension

run_test    "Truncated HMAC: client default, server default" \
            "$P_SRV debug_level=4" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -s "dumping 'expected mac' (20 bytes)" \
            -S "dumping 'expected mac' (10 bytes)"

run_test    "Truncated HMAC: client disabled, server default" \
            "$P_SRV debug_level=4" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             trunc_hmac=0" \
            0 \
            -s "dumping 'expected mac' (20 bytes)" \
            -S "dumping 'expected mac' (10 bytes)"

run_test    "Truncated HMAC: client enabled, server default" \
            "$P_SRV debug_level=4" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -S "dumping 'expected mac' (20 bytes)" \
            -s "dumping 'expected mac' (10 bytes)"

run_test    "Truncated HMAC: client enabled, server disabled" \
            "$P_SRV debug_level=4 trunc_hmac=0" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -s "dumping 'expected mac' (20 bytes)" \
            -S "dumping 'expected mac' (10 bytes)"

run_test    "Truncated HMAC: client enabled, server enabled" \
            "$P_SRV debug_level=4 trunc_hmac=1" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -S "dumping 'expected mac' (20 bytes)" \
            -s "dumping 'expected mac' (10 bytes)"

# Tests for Encrypt-then-MAC extension

run_test    "Encrypt then MAC: default" \
            "$P_SRV debug_level=3 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            "$P_CLI debug_level=3" \
            0 \
            -c "client hello, adding encrypt_then_mac extension" \
            -s "found encrypt then mac extension" \
            -s "server hello, adding encrypt then mac extension" \
            -c "found encrypt_then_mac extension" \
            -c "using encrypt then mac" \
            -s "using encrypt then mac"

run_test    "Encrypt then MAC: client enabled, server disabled" \
            "$P_SRV debug_level=3 etm=0 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            "$P_CLI debug_level=3 etm=1" \
            0 \
            -c "client hello, adding encrypt_then_mac extension" \
            -s "found encrypt then mac extension" \
            -S "server hello, adding encrypt then mac extension" \
            -C "found encrypt_then_mac extension" \
            -C "using encrypt then mac" \
            -S "using encrypt then mac"

run_test    "Encrypt then MAC: client enabled, aead cipher" \
            "$P_SRV debug_level=3 etm=1 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-GCM-SHA256" \
            "$P_CLI debug_level=3 etm=1" \
            0 \
            -c "client hello, adding encrypt_then_mac extension" \
            -s "found encrypt then mac extension" \
            -S "server hello, adding encrypt then mac extension" \
            -C "found encrypt_then_mac extension" \
            -C "using encrypt then mac" \
            -S "using encrypt then mac"

run_test    "Encrypt then MAC: client enabled, stream cipher" \
            "$P_SRV debug_level=3 etm=1 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            "$P_CLI debug_level=3 etm=1 arc4=1" \
            0 \
            -c "client hello, adding encrypt_then_mac extension" \
            -s "found encrypt then mac extension" \
            -S "server hello, adding encrypt then mac extension" \
            -C "found encrypt_then_mac extension" \
            -C "using encrypt then mac" \
            -S "using encrypt then mac"

run_test    "Encrypt then MAC: client disabled, server enabled" \
            "$P_SRV debug_level=3 etm=1 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            "$P_CLI debug_level=3 etm=0" \
            0 \
            -C "client hello, adding encrypt_then_mac extension" \
            -S "found encrypt then mac extension" \
            -S "server hello, adding encrypt then mac extension" \
            -C "found encrypt_then_mac extension" \
            -C "using encrypt then mac" \
            -S "using encrypt then mac"

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Encrypt then MAC: client SSLv3, server enabled" \
            "$P_SRV debug_level=3 min_version=ssl3 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            "$P_CLI debug_level=3 force_version=ssl3" \
            0 \
            -C "client hello, adding encrypt_then_mac extension" \
            -S "found encrypt then mac extension" \
            -S "server hello, adding encrypt then mac extension" \
            -C "found encrypt_then_mac extension" \
            -C "using encrypt then mac" \
            -S "using encrypt then mac"

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Encrypt then MAC: client enabled, server SSLv3" \
            "$P_SRV debug_level=3 force_version=ssl3 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            "$P_CLI debug_level=3 min_version=ssl3" \
            0 \
            -c "client hello, adding encrypt_then_mac extension" \
            -S "found encrypt then mac extension" \
            -S "server hello, adding encrypt then mac extension" \
            -C "found encrypt_then_mac extension" \
            -C "using encrypt then mac" \
            -S "using encrypt then mac"

# Tests for Extended Master Secret extension

run_test    "Extended Master Secret: default" \
            "$P_SRV debug_level=3" \
            "$P_CLI debug_level=3" \
            0 \
            -c "client hello, adding extended_master_secret extension" \
            -s "found extended master secret extension" \
            -s "server hello, adding extended master secret extension" \
            -c "found extended_master_secret extension" \
            -c "using extended master secret" \
            -s "using extended master secret"

run_test    "Extended Master Secret: client enabled, server disabled" \
            "$P_SRV debug_level=3 extended_ms=0" \
            "$P_CLI debug_level=3 extended_ms=1" \
            0 \
            -c "client hello, adding extended_master_secret extension" \
            -s "found extended master secret extension" \
            -S "server hello, adding extended master secret extension" \
            -C "found extended_master_secret extension" \
            -C "using extended master secret" \
            -S "using extended master secret"

run_test    "Extended Master Secret: client disabled, server enabled" \
            "$P_SRV debug_level=3 extended_ms=1" \
            "$P_CLI debug_level=3 extended_ms=0" \
            0 \
            -C "client hello, adding extended_master_secret extension" \
            -S "found extended master secret extension" \
            -S "server hello, adding extended master secret extension" \
            -C "found extended_master_secret extension" \
            -C "using extended master secret" \
            -S "using extended master secret"

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Extended Master Secret: client SSLv3, server enabled" \
            "$P_SRV debug_level=3 min_version=ssl3" \
            "$P_CLI debug_level=3 force_version=ssl3" \
            0 \
            -C "client hello, adding extended_master_secret extension" \
            -S "found extended master secret extension" \
            -S "server hello, adding extended master secret extension" \
            -C "found extended_master_secret extension" \
            -C "using extended master secret" \
            -S "using extended master secret"

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Extended Master Secret: client enabled, server SSLv3" \
            "$P_SRV debug_level=3 force_version=ssl3" \
            "$P_CLI debug_level=3 min_version=ssl3" \
            0 \
            -c "client hello, adding extended_master_secret extension" \
            -S "found extended master secret extension" \
            -S "server hello, adding extended master secret extension" \
            -C "found extended_master_secret extension" \
            -C "using extended master secret" \
            -S "using extended master secret"

# Tests for FALLBACK_SCSV

run_test    "Fallback SCSV: default" \
            "$P_SRV" \
            "$P_CLI debug_level=3 force_version=tls1_1" \
            0 \
            -C "adding FALLBACK_SCSV" \
            -S "received FALLBACK_SCSV" \
            -S "inapropriate fallback" \
            -C "is a fatal alert message (msg 86)"

run_test    "Fallback SCSV: explicitly disabled" \
            "$P_SRV" \
            "$P_CLI debug_level=3 force_version=tls1_1 fallback=0" \
            0 \
            -C "adding FALLBACK_SCSV" \
            -S "received FALLBACK_SCSV" \
            -S "inapropriate fallback" \
            -C "is a fatal alert message (msg 86)"

run_test    "Fallback SCSV: enabled" \
            "$P_SRV" \
            "$P_CLI debug_level=3 force_version=tls1_1 fallback=1" \
            1 \
            -c "adding FALLBACK_SCSV" \
            -s "received FALLBACK_SCSV" \
            -s "inapropriate fallback" \
            -c "is a fatal alert message (msg 86)"

run_test    "Fallback SCSV: enabled, max version" \
            "$P_SRV" \
            "$P_CLI debug_level=3 fallback=1" \
            0 \
            -c "adding FALLBACK_SCSV" \
            -s "received FALLBACK_SCSV" \
            -S "inapropriate fallback" \
            -C "is a fatal alert message (msg 86)"

requires_openssl_with_fallback_scsv
run_test    "Fallback SCSV: default, openssl server" \
            "$O_SRV" \
            "$P_CLI debug_level=3 force_version=tls1_1 fallback=0" \
            0 \
            -C "adding FALLBACK_SCSV" \
            -C "is a fatal alert message (msg 86)"

requires_openssl_with_fallback_scsv
run_test    "Fallback SCSV: enabled, openssl server" \
            "$O_SRV" \
            "$P_CLI debug_level=3 force_version=tls1_1 fallback=1" \
            1 \
            -c "adding FALLBACK_SCSV" \
            -c "is a fatal alert message (msg 86)"

requires_openssl_with_fallback_scsv
run_test    "Fallback SCSV: disabled, openssl client" \
            "$P_SRV" \
            "$O_CLI -tls1_1" \
            0 \
            -S "received FALLBACK_SCSV" \
            -S "inapropriate fallback"

requires_openssl_with_fallback_scsv
run_test    "Fallback SCSV: enabled, openssl client" \
            "$P_SRV" \
            "$O_CLI -tls1_1 -fallback_scsv" \
            1 \
            -s "received FALLBACK_SCSV" \
            -s "inapropriate fallback"

requires_openssl_with_fallback_scsv
run_test    "Fallback SCSV: enabled, max version, openssl client" \
            "$P_SRV" \
            "$O_CLI -fallback_scsv" \
            0 \
            -s "received FALLBACK_SCSV" \
            -S "inapropriate fallback"

## ClientHello generated with
## "openssl s_client -CAfile tests/data_files/test-ca.crt -tls1_1 -connect localhost:4433 -cipher ..."
## then manually twiddling the ciphersuite list.
## The ClientHello content is spelled out below as a hex string as
## "prefix ciphersuite1 ciphersuite2 ciphersuite3 ciphersuite4 suffix".
## The expected response is an inappropriate_fallback alert.
requires_openssl_with_fallback_scsv
run_test    "Fallback SCSV: beginning of list" \
            "$P_SRV debug_level=2" \
            "$TCP_CLIENT localhost $PORT '160301003e0100003a03022aafb94308dc22ca1086c65acc00e414384d76b61ecab37df1633b1ae1034dbe000008 5600 0031 0032 0033 0100000900230000000f000101' '15030200020256'" \
            0 \
            -s "received FALLBACK_SCSV" \
            -s "inapropriate fallback"

requires_openssl_with_fallback_scsv
run_test    "Fallback SCSV: end of list" \
            "$P_SRV debug_level=2" \
            "$TCP_CLIENT localhost $PORT '160301003e0100003a03022aafb94308dc22ca1086c65acc00e414384d76b61ecab37df1633b1ae1034dbe000008 0031 0032 0033 5600 0100000900230000000f000101' '15030200020256'" \
            0 \
            -s "received FALLBACK_SCSV" \
            -s "inapropriate fallback"

## Here the expected response is a valid ServerHello prefix, up to the random.
requires_openssl_with_fallback_scsv
run_test    "Fallback SCSV: not in list" \
            "$P_SRV debug_level=2" \
            "$TCP_CLIENT localhost $PORT '160301003e0100003a03022aafb94308dc22ca1086c65acc00e414384d76b61ecab37df1633b1ae1034dbe000008 0056 0031 0032 0033 0100000900230000000f000101' '16030200300200002c0302'" \
            0 \
            -S "received FALLBACK_SCSV" \
            -S "inapropriate fallback"

# Tests for CBC 1/n-1 record splitting

run_test    "CBC Record splitting: TLS 1.2, no splitting" \
            "$P_SRV" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             request_size=123 force_version=tls1_2" \
            0 \
            -s "Read from client: 123 bytes read" \
            -S "Read from client: 1 bytes read" \
            -S "122 bytes read"

run_test    "CBC Record splitting: TLS 1.1, no splitting" \
            "$P_SRV" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             request_size=123 force_version=tls1_1" \
            0 \
            -s "Read from client: 123 bytes read" \
            -S "Read from client: 1 bytes read" \
            -S "122 bytes read"

run_test    "CBC Record splitting: TLS 1.0, splitting" \
            "$P_SRV" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             request_size=123 force_version=tls1" \
            0 \
            -S "Read from client: 123 bytes read" \
            -s "Read from client: 1 bytes read" \
            -s "122 bytes read"

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "CBC Record splitting: SSLv3, splitting" \
            "$P_SRV min_version=ssl3" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             request_size=123 force_version=ssl3" \
            0 \
            -S "Read from client: 123 bytes read" \
            -s "Read from client: 1 bytes read" \
            -s "122 bytes read"

run_test    "CBC Record splitting: TLS 1.0 RC4, no splitting" \
            "$P_SRV arc4=1" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA \
             request_size=123 force_version=tls1" \
            0 \
            -s "Read from client: 123 bytes read" \
            -S "Read from client: 1 bytes read" \
            -S "122 bytes read"

run_test    "CBC Record splitting: TLS 1.0, splitting disabled" \
            "$P_SRV" \
            "$P_CLI force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             request_size=123 force_version=tls1 recsplit=0" \
            0 \
            -s "Read from client: 123 bytes read" \
            -S "Read from client: 1 bytes read" \
            -S "122 bytes read"

run_test    "CBC Record splitting: TLS 1.0, splitting, nbio" \
            "$P_SRV nbio=2" \
            "$P_CLI nbio=2 force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA \
             request_size=123 force_version=tls1" \
            0 \
            -S "Read from client: 123 bytes read" \
            -s "Read from client: 1 bytes read" \
            -s "122 bytes read"

# Tests for Session Tickets

run_test    "Session resume using tickets: basic" \
            "$P_SRV debug_level=3 tickets=1" \
            "$P_CLI debug_level=3 tickets=1 reconnect=1" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -s "server hello, adding session ticket extension" \
            -c "found session_ticket extension" \
            -c "parse new session ticket" \
            -S "session successfully restored from cache" \
            -s "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using tickets: cache disabled" \
            "$P_SRV debug_level=3 tickets=1 cache_max=0" \
            "$P_CLI debug_level=3 tickets=1 reconnect=1" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -s "server hello, adding session ticket extension" \
            -c "found session_ticket extension" \
            -c "parse new session ticket" \
            -S "session successfully restored from cache" \
            -s "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using tickets: timeout" \
            "$P_SRV debug_level=3 tickets=1 cache_max=0 ticket_timeout=1" \
            "$P_CLI debug_level=3 tickets=1 reconnect=1 reco_delay=2" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -s "server hello, adding session ticket extension" \
            -c "found session_ticket extension" \
            -c "parse new session ticket" \
            -S "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -S "a session has been resumed" \
            -C "a session has been resumed"

run_test    "Session resume using tickets: openssl server" \
            "$O_SRV" \
            "$P_CLI debug_level=3 tickets=1 reconnect=1" \
            0 \
            -c "client hello, adding session ticket extension" \
            -c "found session_ticket extension" \
            -c "parse new session ticket" \
            -c "a session has been resumed"

run_test    "Session resume using tickets: openssl client" \
            "$P_SRV debug_level=3 tickets=1" \
            "( $O_CLI -sess_out $SESSION; \
               $O_CLI -sess_in $SESSION; \
               rm -f $SESSION )" \
            0 \
            -s "found session ticket extension" \
            -s "server hello, adding session ticket extension" \
            -S "session successfully restored from cache" \
            -s "session successfully restored from ticket" \
            -s "a session has been resumed"

# Tests for Session Resume based on session-ID and cache

run_test    "Session resume using cache: tickets enabled on client" \
            "$P_SRV debug_level=3 tickets=0" \
            "$P_CLI debug_level=3 tickets=1 reconnect=1" \
            0 \
            -c "client hello, adding session ticket extension" \
            -s "found session ticket extension" \
            -S "server hello, adding session ticket extension" \
            -C "found session_ticket extension" \
            -C "parse new session ticket" \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache: tickets enabled on server" \
            "$P_SRV debug_level=3 tickets=1" \
            "$P_CLI debug_level=3 tickets=0 reconnect=1" \
            0 \
            -C "client hello, adding session ticket extension" \
            -S "found session ticket extension" \
            -S "server hello, adding session ticket extension" \
            -C "found session_ticket extension" \
            -C "parse new session ticket" \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache: cache_max=0" \
            "$P_SRV debug_level=3 tickets=0 cache_max=0" \
            "$P_CLI debug_level=3 tickets=0 reconnect=1" \
            0 \
            -S "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -S "a session has been resumed" \
            -C "a session has been resumed"

run_test    "Session resume using cache: cache_max=1" \
            "$P_SRV debug_level=3 tickets=0 cache_max=1" \
            "$P_CLI debug_level=3 tickets=0 reconnect=1" \
            0 \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache: timemout > delay" \
            "$P_SRV debug_level=3 tickets=0" \
            "$P_CLI debug_level=3 tickets=0 reconnect=1 reco_delay=0" \
            0 \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache: timeout < delay" \
            "$P_SRV debug_level=3 tickets=0 cache_timeout=1" \
            "$P_CLI debug_level=3 tickets=0 reconnect=1 reco_delay=2" \
            0 \
            -S "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -S "a session has been resumed" \
            -C "a session has been resumed"

run_test    "Session resume using cache: no timeout" \
            "$P_SRV debug_level=3 tickets=0 cache_timeout=0" \
            "$P_CLI debug_level=3 tickets=0 reconnect=1 reco_delay=2" \
            0 \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed" \
            -c "a session has been resumed"

run_test    "Session resume using cache: openssl client" \
            "$P_SRV debug_level=3 tickets=0" \
            "( $O_CLI -sess_out $SESSION; \
               $O_CLI -sess_in $SESSION; \
               rm -f $SESSION )" \
            0 \
            -s "found session ticket extension" \
            -S "server hello, adding session ticket extension" \
            -s "session successfully restored from cache" \
            -S "session successfully restored from ticket" \
            -s "a session has been resumed"

run_test    "Session resume using cache: openssl server" \
            "$O_SRV" \
            "$P_CLI debug_level=3 tickets=0 reconnect=1" \
            0 \
            -C "found session_ticket extension" \
            -C "parse new session ticket" \
            -c "a session has been resumed"

# Tests for Max Fragment Length extension

run_test    "Max fragment length: not used, reference" \
            "$P_SRV debug_level=3" \
            "$P_CLI debug_level=3" \
            0 \
            -C "client hello, adding max_fragment_length extension" \
            -S "found max fragment length extension" \
            -S "server hello, max_fragment_length extension" \
            -C "found max_fragment_length extension"

run_test    "Max fragment length: used by client" \
            "$P_SRV debug_level=3" \
            "$P_CLI debug_level=3 max_frag_len=4096" \
            0 \
            -c "client hello, adding max_fragment_length extension" \
            -s "found max fragment length extension" \
            -s "server hello, max_fragment_length extension" \
            -c "found max_fragment_length extension"

run_test    "Max fragment length: used by server" \
            "$P_SRV debug_level=3 max_frag_len=4096" \
            "$P_CLI debug_level=3" \
            0 \
            -C "client hello, adding max_fragment_length extension" \
            -S "found max fragment length extension" \
            -S "server hello, max_fragment_length extension" \
            -C "found max_fragment_length extension"

requires_gnutls
run_test    "Max fragment length: gnutls server" \
            "$G_SRV" \
            "$P_CLI debug_level=3 max_frag_len=4096" \
            0 \
            -c "client hello, adding max_fragment_length extension" \
            -c "found max_fragment_length extension"

# Tests for renegotiation

run_test    "Renegotiation: none, for reference" \
            "$P_SRV debug_level=3 exchanges=2" \
            "$P_CLI debug_level=3 exchanges=2" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -C "=> renegotiate" \
            -S "=> renegotiate" \
            -S "write hello request"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: client-initiated" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=1 renegotiate=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -S "write hello request"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: server-initiated" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 renegotiate=1" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -s "write hello request"

# Checks that no Signature Algorithm with SHA-1 gets negotiated. Negotiating SHA-1 would mean that
# the server did not parse the Signature Algorithm extension. This test is valid only if an MD
# algorithm stronger than SHA-1 is enabled in config.h
requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: Signature Algorithms parsing, client-initiated" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 auth_mode=optional" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=1 renegotiate=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -S "write hello request" \
            -S "client hello v3, signature_algorithm ext: 2" # Is SHA-1 negotiated?

# Checks that no Signature Algorithm with SHA-1 gets negotiated. Negotiating SHA-1 would mean that
# the server did not parse the Signature Algorithm extension. This test is valid only if an MD
# algorithm stronger than SHA-1 is enabled in config.h
requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: Signature Algorithms parsing, server-initiated" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 auth_mode=optional renegotiate=1" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -s "write hello request" \
            -S "client hello v3, signature_algorithm ext: 2" # Is SHA-1 negotiated?

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: double" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 renegotiate=1" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=1 renegotiate=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -s "write hello request"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: client-initiated, server-rejected" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=0" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=1 renegotiate=1" \
            1 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -S "=> renegotiate" \
            -S "write hello request" \
            -c "SSL - Unexpected message at ServerHello in renegotiation" \
            -c "failed"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: server-initiated, client-rejected, default" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 renegotiate=1" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=0" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -C "=> renegotiate" \
            -S "=> renegotiate" \
            -s "write hello request" \
            -S "SSL - An unexpected message was received from our peer" \
            -S "failed"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: server-initiated, client-rejected, not enforced" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 renegotiate=1 \
             renego_delay=-1" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=0" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -C "=> renegotiate" \
            -S "=> renegotiate" \
            -s "write hello request" \
            -S "SSL - An unexpected message was received from our peer" \
            -S "failed"

# delay 2 for 1 alert record + 1 application data record
requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: server-initiated, client-rejected, delay 2" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 renegotiate=1 \
             renego_delay=2" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=0" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -C "=> renegotiate" \
            -S "=> renegotiate" \
            -s "write hello request" \
            -S "SSL - An unexpected message was received from our peer" \
            -S "failed"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: server-initiated, client-rejected, delay 0" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 renegotiate=1 \
             renego_delay=0" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=0" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -C "=> renegotiate" \
            -S "=> renegotiate" \
            -s "write hello request" \
            -s "SSL - An unexpected message was received from our peer"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: server-initiated, client-accepted, delay 0" \
            "$P_SRV debug_level=3 exchanges=2 renegotiation=1 renegotiate=1 \
             renego_delay=0" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -s "write hello request" \
            -S "SSL - An unexpected message was received from our peer" \
            -S "failed"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: periodic, just below period" \
            "$P_SRV debug_level=3 exchanges=9 renegotiation=1 renego_period=3" \
            "$P_CLI debug_level=3 exchanges=2 renegotiation=1" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -S "record counter limit reached: renegotiate" \
            -C "=> renegotiate" \
            -S "=> renegotiate" \
            -S "write hello request" \
            -S "SSL - An unexpected message was received from our peer" \
            -S "failed"

# one extra exchange to be able to complete renego
requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: periodic, just above period" \
            "$P_SRV debug_level=3 exchanges=9 renegotiation=1 renego_period=3" \
            "$P_CLI debug_level=3 exchanges=4 renegotiation=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -s "record counter limit reached: renegotiate" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -s "write hello request" \
            -S "SSL - An unexpected message was received from our peer" \
            -S "failed"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: periodic, two times period" \
            "$P_SRV debug_level=3 exchanges=9 renegotiation=1 renego_period=3" \
            "$P_CLI debug_level=3 exchanges=7 renegotiation=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -s "record counter limit reached: renegotiate" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -s "write hello request" \
            -S "SSL - An unexpected message was received from our peer" \
            -S "failed"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: periodic, above period, disabled" \
            "$P_SRV debug_level=3 exchanges=9 renegotiation=0 renego_period=3" \
            "$P_CLI debug_level=3 exchanges=4 renegotiation=1" \
            0 \
            -C "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -S "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -S "record counter limit reached: renegotiate" \
            -C "=> renegotiate" \
            -S "=> renegotiate" \
            -S "write hello request" \
            -S "SSL - An unexpected message was received from our peer" \
            -S "failed"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: nbio, client-initiated" \
            "$P_SRV debug_level=3 nbio=2 exchanges=2 renegotiation=1" \
            "$P_CLI debug_level=3 nbio=2 exchanges=2 renegotiation=1 renegotiate=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -S "write hello request"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: nbio, server-initiated" \
            "$P_SRV debug_level=3 nbio=2 exchanges=2 renegotiation=1 renegotiate=1" \
            "$P_CLI debug_level=3 nbio=2 exchanges=2 renegotiation=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO" \
            -s "found renegotiation extension" \
            -s "server hello, secure renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -s "=> renegotiate" \
            -s "write hello request"

requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: openssl server, client-initiated" \
            "$O_SRV" \
            "$P_CLI debug_level=3 exchanges=1 renegotiation=1 renegotiate=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -C "ssl_hanshake() returned" \
            -C "error" \
            -c "HTTP/1.0 200 [Oo][Kk]"

requires_gnutls
requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: gnutls server strict, client-initiated" \
            "$G_SRV --priority=NORMAL:%SAFE_RENEGOTIATION" \
            "$P_CLI debug_level=3 exchanges=1 renegotiation=1 renegotiate=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -c "found renegotiation extension" \
            -c "=> renegotiate" \
            -C "ssl_hanshake() returned" \
            -C "error" \
            -c "HTTP/1.0 200 [Oo][Kk]"

requires_gnutls
requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: gnutls server unsafe, client-initiated default" \
            "$G_SRV --priority=NORMAL:%DISABLE_SAFE_RENEGOTIATION" \
            "$P_CLI debug_level=3 exchanges=1 renegotiation=1 renegotiate=1" \
            1 \
            -c "client hello, adding renegotiation extension" \
            -C "found renegotiation extension" \
            -c "=> renegotiate" \
            -c "ssl_handshake() returned" \
            -c "error" \
            -C "HTTP/1.0 200 [Oo][Kk]"

requires_gnutls
requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: gnutls server unsafe, client-inititated no legacy" \
            "$G_SRV --priority=NORMAL:%DISABLE_SAFE_RENEGOTIATION" \
            "$P_CLI debug_level=3 exchanges=1 renegotiation=1 renegotiate=1 \
             allow_legacy=0" \
            1 \
            -c "client hello, adding renegotiation extension" \
            -C "found renegotiation extension" \
            -c "=> renegotiate" \
            -c "ssl_handshake() returned" \
            -c "error" \
            -C "HTTP/1.0 200 [Oo][Kk]"

requires_gnutls
requires_config_disabled POLARSSL_SSL_DISABLE_RENEGOTIATION
run_test    "Renegotiation: gnutls server unsafe, client-inititated legacy" \
            "$G_SRV --priority=NORMAL:%DISABLE_SAFE_RENEGOTIATION" \
            "$P_CLI debug_level=3 exchanges=1 renegotiation=1 renegotiate=1 \
             allow_legacy=1" \
            0 \
            -c "client hello, adding renegotiation extension" \
            -C "found renegotiation extension" \
            -c "=> renegotiate" \
            -C "ssl_hanshake() returned" \
            -C "error" \
            -c "HTTP/1.0 200 [Oo][Kk]"

# Test for the "secure renegotation" extension only (no actual renegotiation)

requires_gnutls
run_test    "Renego ext: gnutls server strict, client default" \
            "$G_SRV --priority=NORMAL:%SAFE_RENEGOTIATION" \
            "$P_CLI debug_level=3" \
            0 \
            -c "found renegotiation extension" \
            -C "error" \
            -c "HTTP/1.0 200 [Oo][Kk]"

requires_gnutls
run_test    "Renego ext: gnutls server unsafe, client default" \
            "$G_SRV --priority=NORMAL:%DISABLE_SAFE_RENEGOTIATION" \
            "$P_CLI debug_level=3" \
            0 \
            -C "found renegotiation extension" \
            -C "error" \
            -c "HTTP/1.0 200 [Oo][Kk]"

requires_gnutls
run_test    "Renego ext: gnutls server unsafe, client break legacy" \
            "$G_SRV --priority=NORMAL:%DISABLE_SAFE_RENEGOTIATION" \
            "$P_CLI debug_level=3 allow_legacy=-1" \
            1 \
            -C "found renegotiation extension" \
            -c "error" \
            -C "HTTP/1.0 200 [Oo][Kk]"

requires_gnutls
run_test    "Renego ext: gnutls client strict, server default" \
            "$P_SRV debug_level=3" \
            "$G_CLI --priority=NORMAL:%SAFE_RENEGOTIATION" \
            0 \
            -s "received TLS_EMPTY_RENEGOTIATION_INFO\|found renegotiation extension" \
            -s "server hello, secure renegotiation extension"

requires_gnutls
run_test    "Renego ext: gnutls client unsafe, server default" \
            "$P_SRV debug_level=3" \
            "$G_CLI --priority=NORMAL:%DISABLE_SAFE_RENEGOTIATION" \
            0 \
            -S "received TLS_EMPTY_RENEGOTIATION_INFO\|found renegotiation extension" \
            -S "server hello, secure renegotiation extension"

requires_gnutls
run_test    "Renego ext: gnutls client unsafe, server break legacy" \
            "$P_SRV debug_level=3 allow_legacy=-1" \
            "$G_CLI --priority=NORMAL:%DISABLE_SAFE_RENEGOTIATION" \
            1 \
            -S "received TLS_EMPTY_RENEGOTIATION_INFO\|found renegotiation extension" \
            -S "server hello, secure renegotiation extension"

# Tests for auth_mode

run_test    "Authentication: server badcert, client required" \
            "$P_SRV crt_file=data_files/server5-badsign.crt \
             key_file=data_files/server5.key" \
            "$P_CLI debug_level=1 auth_mode=required" \
            1 \
            -c "x509_verify_cert() returned" \
            -c "! The certificate is not correctly signed by the trusted CA" \
            -c "! ssl_handshake returned" \
            -c "X509 - Certificate verification failed"

run_test    "Authentication: server badcert, client optional" \
            "$P_SRV crt_file=data_files/server5-badsign.crt \
             key_file=data_files/server5.key" \
            "$P_CLI debug_level=1 auth_mode=optional" \
            0 \
            -c "x509_verify_cert() returned" \
            -c "! The certificate is not correctly signed by the trusted CA" \
            -C "! ssl_handshake returned" \
            -C "X509 - Certificate verification failed"

run_test    "Authentication: server goodcert, client optional, no trusted CA" \
            "$P_SRV" \
            "$P_CLI debug_level=3 auth_mode=optional ca_file=none ca_path=none" \
            0 \
            -c "x509_verify_cert() returned" \
            -c "! The certificate is not correctly signed by the trusted CA" \
            -c "! Certificate verification flags"\
            -C "! ssl_handshake returned" \
            -C "X509 - Certificate verification failed" \
            -C "SSL - No CA Chain is set, but required to operate"

run_test    "Authentication: server goodcert, client required, no trusted CA" \
            "$P_SRV" \
            "$P_CLI debug_level=3 auth_mode=required ca_file=none ca_path=none" \
            1 \
            -c "x509_verify_cert() returned" \
            -c "! The certificate is not correctly signed by the trusted CA" \
            -c "! Certificate verification flags"\
            -c "! ssl_handshake returned" \
            -c "SSL - No CA Chain is set, but required to operate"

# The purpose of the next two tests is to test the client's behaviour when receiving a server
# certificate with an unsupported elliptic curve. This should usually not happen because
# the client informs the server about the supported curves - it does, though, in the
# corner case of a static ECDH suite, because the server doesn't check the curve on that
# occasion (to be fixed). If that bug's fixed, the test needs to be altered to use a
# different means to have the server ignoring the client's supported curve list.

requires_config_enabled POLARSSL_SSL_SET_CURVES
run_test    "Authentication: server ECDH p256v1, client required, p256v1 unsupported" \
            "$P_SRV debug_level=1 key_file=data_files/server5.key \
             crt_file=data_files/server5.ku-ka.crt" \
            "$P_CLI debug_level=3 auth_mode=required curves=secp521r1" \
            1 \
            -c "bad certificate (EC key curve)"\
            -c "! Certificate verification flags"\
            -C "bad server certificate (ECDH curve)" # Expect failure at earlier verification stage

requires_config_enabled POLARSSL_SSL_SET_CURVES
run_test    "Authentication: server ECDH p256v1, client optional, p256v1 unsupported" \
            "$P_SRV debug_level=1 key_file=data_files/server5.key \
             crt_file=data_files/server5.ku-ka.crt" \
            "$P_CLI debug_level=3 auth_mode=optional curves=secp521r1" \
            1 \
            -c "bad certificate (EC key curve)"\
            -c "! Certificate verification flags"\
            -c "bad server certificate (ECDH curve)" # Expect failure only at ECDH params check

run_test    "Authentication: server badcert, client none" \
            "$P_SRV crt_file=data_files/server5-badsign.crt \
             key_file=data_files/server5.key" \
            "$P_CLI debug_level=1 auth_mode=none" \
            0 \
            -C "x509_verify_cert() returned" \
            -C "! The certificate is not correctly signed by the trusted CA" \
            -C "! ssl_handshake returned" \
            -C "X509 - Certificate verification failed"

run_test    "Authentication: client badcert, server required" \
            "$P_SRV debug_level=3 auth_mode=required" \
            "$P_CLI debug_level=3 crt_file=data_files/server5-badsign.crt \
             key_file=data_files/server5.key" \
            1 \
            -S "skip write certificate request" \
            -C "skip parse certificate request" \
            -c "got a certificate request" \
            -C "skip write certificate" \
            -C "skip write certificate verify" \
            -S "skip parse certificate verify" \
            -s "x509_verify_cert() returned" \
            -S "! The certificate is not correctly signed by the trusted CA" \
            -s "! ssl_handshake returned" \
            -c "! ssl_handshake returned" \
            -s "X509 - Certificate verification failed"

run_test    "Authentication: client badcert, server optional" \
            "$P_SRV debug_level=3 auth_mode=optional" \
            "$P_CLI debug_level=3 crt_file=data_files/server5-badsign.crt \
             key_file=data_files/server5.key" \
            0 \
            -S "skip write certificate request" \
            -C "skip parse certificate request" \
            -c "got a certificate request" \
            -C "skip write certificate" \
            -C "skip write certificate verify" \
            -S "skip parse certificate verify" \
            -s "x509_verify_cert() returned" \
            -s "! The certificate is not correctly signed by the trusted CA" \
            -S "! ssl_handshake returned" \
            -C "! ssl_handshake returned" \
            -S "X509 - Certificate verification failed"

run_test    "Authentication: client badcert, server none" \
            "$P_SRV debug_level=3 auth_mode=none" \
            "$P_CLI debug_level=3 crt_file=data_files/server5-badsign.crt \
             key_file=data_files/server5.key" \
            0 \
            -s "skip write certificate request" \
            -C "skip parse certificate request" \
            -c "got no certificate request" \
            -c "skip write certificate" \
            -c "skip write certificate verify" \
            -s "skip parse certificate verify" \
            -S "x509_verify_cert() returned" \
            -S "! The certificate is not correctly signed by the trusted CA" \
            -S "! ssl_handshake returned" \
            -C "! ssl_handshake returned" \
            -S "X509 - Certificate verification failed"

run_test    "Authentication: client no cert, server optional" \
            "$P_SRV debug_level=3 auth_mode=optional" \
            "$P_CLI debug_level=3 crt_file=none key_file=none" \
            0 \
            -S "skip write certificate request" \
            -C "skip parse certificate request" \
            -c "got a certificate request" \
            -C "skip write certificate$" \
            -C "got no certificate to send" \
            -S "SSLv3 client has no certificate" \
            -c "skip write certificate verify" \
            -s "skip parse certificate verify" \
            -s "! Certificate was missing" \
            -S "! ssl_handshake returned" \
            -C "! ssl_handshake returned" \
            -S "X509 - Certificate verification failed"

run_test    "Authentication: openssl client no cert, server optional" \
            "$P_SRV debug_level=3 auth_mode=optional" \
            "$O_CLI" \
            0 \
            -S "skip write certificate request" \
            -s "skip parse certificate verify" \
            -s "! Certificate was missing" \
            -S "! ssl_handshake returned" \
            -S "X509 - Certificate verification failed"

run_test    "Authentication: client no cert, openssl server optional" \
            "$O_SRV -verify 10" \
            "$P_CLI debug_level=3 crt_file=none key_file=none" \
            0 \
            -C "skip parse certificate request" \
            -c "got a certificate request" \
            -C "skip write certificate$" \
            -c "skip write certificate verify" \
            -C "! ssl_handshake returned"

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Authentication: client no cert, ssl3" \
            "$P_SRV debug_level=3 auth_mode=optional force_version=ssl3" \
            "$P_CLI debug_level=3 crt_file=none key_file=none min_version=ssl3" \
            0 \
            -S "skip write certificate request" \
            -C "skip parse certificate request" \
            -c "got a certificate request" \
            -C "skip write certificate$" \
            -c "skip write certificate verify" \
            -c "got no certificate to send" \
            -s "SSLv3 client has no certificate" \
            -s "skip parse certificate verify" \
            -s "! Certificate was missing" \
            -S "! ssl_handshake returned" \
            -C "! ssl_handshake returned" \
            -S "X509 - Certificate verification failed"

run_test    "Authentication: server max_int chain, client default" \
            "$P_SRV crt_file=data_files/dir-maxpath/c09.pem \
                    key_file=data_files/dir-maxpath/09.key" \
            "$P_CLI server_name=CA09 server_addr=127.0.0.1 \
                    ca_file=data_files/dir-maxpath/00.crt" \
            0 \
            -C "X509 - A fatal error occured"

run_test    "Authentication: server max_int+1 chain, client default" \
            "$P_SRV crt_file=data_files/dir-maxpath/c10.pem \
                    key_file=data_files/dir-maxpath/10.key" \
            "$P_CLI server_name=CA10 server_addr=127.0.0.1 \
                    ca_file=data_files/dir-maxpath/00.crt" \
            1 \
            -c "X509 - A fatal error occured"

run_test    "Authentication: server max_int+1 chain, client optional" \
            "$P_SRV crt_file=data_files/dir-maxpath/c10.pem \
                    key_file=data_files/dir-maxpath/10.key" \
            "$P_CLI server_name=CA10 server_addr=127.0.0.1 \
                    ca_file=data_files/dir-maxpath/00.crt \
                    auth_mode=optional" \
            1 \
            -c "X509 - A fatal error occured"

run_test    "Authentication: server max_int+1 chain, client none" \
            "$P_SRV crt_file=data_files/dir-maxpath/c10.pem \
                    key_file=data_files/dir-maxpath/10.key" \
            "$P_CLI server_name=CA10 server_addr=127.0.0.1 ca_file=data_files/dir-maxpath/00.crt \
                    auth_mode=none" \
            0 \
            -C "X509 - A fatal error occured"

run_test    "Authentication: client max_int+1 chain, server none" \
            "$P_SRV ca_file=data_files/dir-maxpath/00.crt auth_mode=none" \
            "$P_CLI crt_file=data_files/dir-maxpath/c10.pem \
                    key_file=data_files/dir-maxpath/10.key" \
            0 \
            -S "X509 - A fatal error occured"

run_test    "Authentication: client max_int+1 chain, server optional" \
            "$P_SRV ca_file=data_files/dir-maxpath/00.crt auth_mode=optional" \
            "$P_CLI crt_file=data_files/dir-maxpath/c10.pem \
                    key_file=data_files/dir-maxpath/10.key" \
            1 \
            -s "X509 - A fatal error occured"

run_test    "Authentication: client max_int+1 chain, server required" \
            "$P_SRV ca_file=data_files/dir-maxpath/00.crt auth_mode=required" \
            "$P_CLI crt_file=data_files/dir-maxpath/c10.pem \
                    key_file=data_files/dir-maxpath/10.key" \
            1 \
            -s "X509 - A fatal error occured"

run_test    "Authentication: client max_int chain, server required" \
            "$P_SRV ca_file=data_files/dir-maxpath/00.crt auth_mode=required" \
            "$P_CLI crt_file=data_files/dir-maxpath/c09.pem \
                    key_file=data_files/dir-maxpath/09.key" \
            0 \
            -S "X509 - A fatal error occured"

# Tests for certificate selection based on SHA verson

run_test    "Certificate hash: client TLS 1.2 -> SHA-2" \
            "$P_SRV crt_file=data_files/server5.crt \
                    key_file=data_files/server5.key \
                    crt_file2=data_files/server5-sha1.crt \
                    key_file2=data_files/server5.key" \
            "$P_CLI force_version=tls1_2" \
            0 \
            -c "signed using.*ECDSA with SHA256" \
            -C "signed using.*ECDSA with SHA1"

run_test    "Certificate hash: client TLS 1.1 -> SHA-1" \
            "$P_SRV crt_file=data_files/server5.crt \
                    key_file=data_files/server5.key \
                    crt_file2=data_files/server5-sha1.crt \
                    key_file2=data_files/server5.key" \
            "$P_CLI force_version=tls1_1" \
            0 \
            -C "signed using.*ECDSA with SHA256" \
            -c "signed using.*ECDSA with SHA1"

run_test    "Certificate hash: client TLS 1.0 -> SHA-1" \
            "$P_SRV crt_file=data_files/server5.crt \
                    key_file=data_files/server5.key \
                    crt_file2=data_files/server5-sha1.crt \
                    key_file2=data_files/server5.key" \
            "$P_CLI force_version=tls1" \
            0 \
            -C "signed using.*ECDSA with SHA256" \
            -c "signed using.*ECDSA with SHA1"

run_test    "Certificate hash: client TLS 1.1, no SHA-1 -> SHA-2 (order 1)" \
            "$P_SRV crt_file=data_files/server5.crt \
                    key_file=data_files/server5.key \
                    crt_file2=data_files/server6.crt \
                    key_file2=data_files/server6.key" \
            "$P_CLI force_version=tls1_1" \
            0 \
            -c "serial number.*09" \
            -c "signed using.*ECDSA with SHA256" \
            -C "signed using.*ECDSA with SHA1"

run_test    "Certificate hash: client TLS 1.1, no SHA-1 -> SHA-2 (order 2)" \
            "$P_SRV crt_file=data_files/server6.crt \
                    key_file=data_files/server6.key \
                    crt_file2=data_files/server5.crt \
                    key_file2=data_files/server5.key" \
            "$P_CLI force_version=tls1_1" \
            0 \
            -c "serial number.*0A" \
            -c "signed using.*ECDSA with SHA256" \
            -C "signed using.*ECDSA with SHA1"

# tests for SNI

run_test    "SNI: no SNI callback" \
            "$P_SRV debug_level=3 server_addr=127.0.0.1 \
             crt_file=data_files/server5.crt key_file=data_files/server5.key" \
            "$P_CLI debug_level=0 server_addr=127.0.0.1 \
             server_name=localhost" \
             0 \
             -S "parse ServerName extension" \
             -c "issuer name *: C=NL, O=PolarSSL, CN=Polarssl Test EC CA" \
             -c "subject name *: C=NL, O=PolarSSL, CN=localhost"

run_test    "SNI: matching cert 1" \
            "$P_SRV debug_level=3 server_addr=127.0.0.1 \
             crt_file=data_files/server5.crt key_file=data_files/server5.key \
             sni=localhost,data_files/server2.crt,data_files/server2.key,polarssl.example,data_files/server1-nospace.crt,data_files/server1.key" \
            "$P_CLI debug_level=0 server_addr=127.0.0.1 \
             server_name=localhost" \
             0 \
             -s "parse ServerName extension" \
             -c "issuer name *: C=NL, O=PolarSSL, CN=PolarSSL Test CA" \
             -c "subject name *: C=NL, O=PolarSSL, CN=localhost"

run_test    "SNI: matching cert 2" \
            "$P_SRV debug_level=3 server_addr=127.0.0.1 \
             crt_file=data_files/server5.crt key_file=data_files/server5.key \
             sni=localhost,data_files/server2.crt,data_files/server2.key,polarssl.example,data_files/server1-nospace.crt,data_files/server1.key" \
            "$P_CLI debug_level=0 server_addr=127.0.0.1 \
             server_name=polarssl.example" \
             0 \
             -s "parse ServerName extension" \
             -c "issuer name *: C=NL, O=PolarSSL, CN=PolarSSL Test CA" \
             -c "subject name *: C=NL, O=PolarSSL, CN=polarssl.example"

run_test    "SNI: no matching cert" \
            "$P_SRV debug_level=3 server_addr=127.0.0.1 \
             crt_file=data_files/server5.crt key_file=data_files/server5.key \
             sni=localhost,data_files/server2.crt,data_files/server2.key,polarssl.example,data_files/server1-nospace.crt,data_files/server1.key" \
            "$P_CLI debug_level=0 server_addr=127.0.0.1 \
             server_name=nonesuch.example" \
             1 \
             -s "parse ServerName extension" \
             -s "ssl_sni_wrapper() returned" \
             -s "ssl_handshake returned" \
             -c "ssl_handshake returned" \
             -c "SSL - A fatal alert message was received from our peer"

# Tests for non-blocking I/O: exercise a variety of handshake flows

run_test    "Non-blocking I/O: basic handshake" \
            "$P_SRV nbio=2 tickets=0 auth_mode=none" \
            "$P_CLI nbio=2 tickets=0" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -c "Read from server: .* bytes read"

run_test    "Non-blocking I/O: client auth" \
            "$P_SRV nbio=2 tickets=0 auth_mode=required" \
            "$P_CLI nbio=2 tickets=0" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -c "Read from server: .* bytes read"

run_test    "Non-blocking I/O: ticket" \
            "$P_SRV nbio=2 tickets=1 auth_mode=none" \
            "$P_CLI nbio=2 tickets=1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -c "Read from server: .* bytes read"

run_test    "Non-blocking I/O: ticket + client auth" \
            "$P_SRV nbio=2 tickets=1 auth_mode=required" \
            "$P_CLI nbio=2 tickets=1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -c "Read from server: .* bytes read"

run_test    "Non-blocking I/O: ticket + client auth + resume" \
            "$P_SRV nbio=2 tickets=1 auth_mode=required" \
            "$P_CLI nbio=2 tickets=1 reconnect=1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -c "Read from server: .* bytes read"

run_test    "Non-blocking I/O: ticket + resume" \
            "$P_SRV nbio=2 tickets=1 auth_mode=none" \
            "$P_CLI nbio=2 tickets=1 reconnect=1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -c "Read from server: .* bytes read"

run_test    "Non-blocking I/O: session-id resume" \
            "$P_SRV nbio=2 tickets=0 auth_mode=none" \
            "$P_CLI nbio=2 tickets=0 reconnect=1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -c "Read from server: .* bytes read"

# Tests for version negotiation

run_test    "Version check: all -> 1.2" \
            "$P_SRV" \
            "$P_CLI" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -s "Protocol is TLSv1.2" \
            -c "Protocol is TLSv1.2"

run_test    "Version check: cli max 1.1 -> 1.1" \
            "$P_SRV" \
            "$P_CLI max_version=tls1_1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -s "Protocol is TLSv1.1" \
            -c "Protocol is TLSv1.1"

run_test    "Version check: srv max 1.1 -> 1.1" \
            "$P_SRV max_version=tls1_1" \
            "$P_CLI" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -s "Protocol is TLSv1.1" \
            -c "Protocol is TLSv1.1"

run_test    "Version check: cli+srv max 1.1 -> 1.1" \
            "$P_SRV max_version=tls1_1" \
            "$P_CLI max_version=tls1_1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -s "Protocol is TLSv1.1" \
            -c "Protocol is TLSv1.1"

run_test    "Version check: cli max 1.1, srv min 1.1 -> 1.1" \
            "$P_SRV min_version=tls1_1" \
            "$P_CLI max_version=tls1_1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -s "Protocol is TLSv1.1" \
            -c "Protocol is TLSv1.1"

run_test    "Version check: cli min 1.1, srv max 1.1 -> 1.1" \
            "$P_SRV max_version=tls1_1" \
            "$P_CLI min_version=tls1_1" \
            0 \
            -S "ssl_handshake returned" \
            -C "ssl_handshake returned" \
            -s "Protocol is TLSv1.1" \
            -c "Protocol is TLSv1.1"

run_test    "Version check: cli min 1.2, srv max 1.1 -> fail" \
            "$P_SRV max_version=tls1_1" \
            "$P_CLI min_version=tls1_2" \
            1 \
            -s "ssl_handshake returned" \
            -c "ssl_handshake returned" \
            -c "SSL - Handshake protocol not within min/max boundaries"

run_test    "Version check: srv min 1.2, cli max 1.1 -> fail" \
            "$P_SRV min_version=tls1_2" \
            "$P_CLI max_version=tls1_1" \
            1 \
            -s "ssl_handshake returned" \
            -c "ssl_handshake returned" \
            -s "SSL - Handshake protocol not within min/max boundaries"

# Tests for ALPN extension

if grep '^#define POLARSSL_SSL_ALPN' $CONFIG_H >/dev/null; then

run_test    "ALPN: none" \
            "$P_SRV debug_level=3" \
            "$P_CLI debug_level=3" \
            0 \
            -C "client hello, adding alpn extension" \
            -S "found alpn extension" \
            -C "got an alert message, type: \\[2:120]" \
            -S "server hello, adding alpn extension" \
            -C "found alpn extension " \
            -C "Application Layer Protocol is" \
            -S "Application Layer Protocol is"

run_test    "ALPN: client only" \
            "$P_SRV debug_level=3" \
            "$P_CLI debug_level=3 alpn=abc,1234" \
            0 \
            -c "client hello, adding alpn extension" \
            -s "found alpn extension" \
            -C "got an alert message, type: \\[2:120]" \
            -S "server hello, adding alpn extension" \
            -C "found alpn extension " \
            -c "Application Layer Protocol is (none)" \
            -S "Application Layer Protocol is"

run_test    "ALPN: server only" \
            "$P_SRV debug_level=3 alpn=abc,1234" \
            "$P_CLI debug_level=3" \
            0 \
            -C "client hello, adding alpn extension" \
            -S "found alpn extension" \
            -C "got an alert message, type: \\[2:120]" \
            -S "server hello, adding alpn extension" \
            -C "found alpn extension " \
            -C "Application Layer Protocol is" \
            -s "Application Layer Protocol is (none)"

run_test    "ALPN: both, common cli1-srv1" \
            "$P_SRV debug_level=3 alpn=abc,1234" \
            "$P_CLI debug_level=3 alpn=abc,1234" \
            0 \
            -c "client hello, adding alpn extension" \
            -s "found alpn extension" \
            -C "got an alert message, type: \\[2:120]" \
            -s "server hello, adding alpn extension" \
            -c "found alpn extension" \
            -c "Application Layer Protocol is abc" \
            -s "Application Layer Protocol is abc"

run_test    "ALPN: both, common cli2-srv1" \
            "$P_SRV debug_level=3 alpn=abc,1234" \
            "$P_CLI debug_level=3 alpn=1234,abc" \
            0 \
            -c "client hello, adding alpn extension" \
            -s "found alpn extension" \
            -C "got an alert message, type: \\[2:120]" \
            -s "server hello, adding alpn extension" \
            -c "found alpn extension" \
            -c "Application Layer Protocol is abc" \
            -s "Application Layer Protocol is abc"

run_test    "ALPN: both, common cli1-srv2" \
            "$P_SRV debug_level=3 alpn=abc,1234" \
            "$P_CLI debug_level=3 alpn=1234,abcde" \
            0 \
            -c "client hello, adding alpn extension" \
            -s "found alpn extension" \
            -C "got an alert message, type: \\[2:120]" \
            -s "server hello, adding alpn extension" \
            -c "found alpn extension" \
            -c "Application Layer Protocol is 1234" \
            -s "Application Layer Protocol is 1234"

run_test    "ALPN: both, no common" \
            "$P_SRV debug_level=3 alpn=abc,123" \
            "$P_CLI debug_level=3 alpn=1234,abcde" \
            1 \
            -c "client hello, adding alpn extension" \
            -s "found alpn extension" \
            -c "got an alert message, type: \\[2:120]" \
            -S "server hello, adding alpn extension" \
            -C "found alpn extension" \
            -C "Application Layer Protocol is 1234" \
            -S "Application Layer Protocol is 1234"

fi

# Tests for keyUsage in leaf certificates, part 1:
# server-side certificate/suite selection

run_test    "keyUsage srv: RSA, digitalSignature -> (EC)DHE-RSA" \
            "$P_SRV key_file=data_files/server2.key \
             crt_file=data_files/server2.ku-ds.crt" \
            "$P_CLI" \
            0 \
            -c "Ciphersuite is TLS-[EC]*DHE-RSA-WITH-"


run_test    "keyUsage srv: RSA, keyEncipherment -> RSA" \
            "$P_SRV key_file=data_files/server2.key \
             crt_file=data_files/server2.ku-ke.crt" \
            "$P_CLI" \
            0 \
            -c "Ciphersuite is TLS-RSA-WITH-"

run_test    "keyUsage srv: RSA, keyAgreement -> fail" \
            "$P_SRV key_file=data_files/server2.key \
             crt_file=data_files/server2.ku-ka.crt" \
            "$P_CLI" \
            1 \
            -C "Ciphersuite is "

run_test    "keyUsage srv: ECDSA, digitalSignature -> ECDHE-ECDSA" \
            "$P_SRV key_file=data_files/server5.key \
             crt_file=data_files/server5.ku-ds.crt" \
            "$P_CLI" \
            0 \
            -c "Ciphersuite is TLS-ECDHE-ECDSA-WITH-"


run_test    "keyUsage srv: ECDSA, keyAgreement -> ECDH-" \
            "$P_SRV key_file=data_files/server5.key \
             crt_file=data_files/server5.ku-ka.crt" \
            "$P_CLI" \
            0 \
            -c "Ciphersuite is TLS-ECDH-"

run_test    "keyUsage srv: ECDSA, keyEncipherment -> fail" \
            "$P_SRV key_file=data_files/server5.key \
             crt_file=data_files/server5.ku-ke.crt" \
            "$P_CLI" \
            1 \
            -C "Ciphersuite is "

# Tests for keyUsage in leaf certificates, part 2:
# client-side checking of server cert

run_test    "keyUsage cli: DigitalSignature+KeyEncipherment, RSA: OK" \
            "$O_SRV -key data_files/server2.key \
             -cert data_files/server2.ku-ds_ke.crt" \
            "$P_CLI debug_level=1 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -C "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-"

run_test    "keyUsage cli: DigitalSignature+KeyEncipherment, DHE-RSA: OK" \
            "$O_SRV -key data_files/server2.key \
             -cert data_files/server2.ku-ds_ke.crt" \
            "$P_CLI debug_level=1 \
             force_ciphersuite=TLS-DHE-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -C "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-"

run_test    "keyUsage cli: KeyEncipherment, RSA: OK" \
            "$O_SRV -key data_files/server2.key \
             -cert data_files/server2.ku-ke.crt" \
            "$P_CLI debug_level=1 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -C "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-"

run_test    "keyUsage cli: KeyEncipherment, DHE-RSA: fail" \
            "$O_SRV -key data_files/server2.key \
             -cert data_files/server2.ku-ke.crt" \
            "$P_CLI debug_level=1 \
             force_ciphersuite=TLS-DHE-RSA-WITH-AES-128-CBC-SHA" \
            1 \
            -c "bad certificate (usage extensions)" \
            -c "Processing of the Certificate handshake message failed" \
            -C "Ciphersuite is TLS-"

run_test    "keyUsage cli: KeyEncipherment, DHE-RSA: fail, soft" \
            "$O_SRV -key data_files/server2.key \
             -cert data_files/server2.ku-ke.crt" \
            "$P_CLI debug_level=1 auth_mode=optional \
             force_ciphersuite=TLS-DHE-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -c "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-" \
            -c "! Usage does not match the keyUsage extension"

run_test    "keyUsage cli: DigitalSignature, DHE-RSA: OK" \
            "$O_SRV -key data_files/server2.key \
             -cert data_files/server2.ku-ds.crt" \
            "$P_CLI debug_level=1 \
             force_ciphersuite=TLS-DHE-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -C "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-"

run_test    "keyUsage cli: DigitalSignature, RSA: fail" \
            "$O_SRV -key data_files/server2.key \
             -cert data_files/server2.ku-ds.crt" \
            "$P_CLI debug_level=1 \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            1 \
            -c "bad certificate (usage extensions)" \
            -c "Processing of the Certificate handshake message failed" \
            -C "Ciphersuite is TLS-"

run_test    "keyUsage cli: DigitalSignature, RSA: fail, soft" \
            "$O_SRV -key data_files/server2.key \
             -cert data_files/server2.ku-ds.crt" \
            "$P_CLI debug_level=1 auth_mode=optional \
             force_ciphersuite=TLS-RSA-WITH-AES-128-CBC-SHA" \
            0 \
            -c "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-" \
            -c "! Usage does not match the keyUsage extension"

# Tests for keyUsage in leaf certificates, part 3:
# server-side checking of client cert

run_test    "keyUsage cli-auth: RSA, DigitalSignature: OK" \
            "$P_SRV debug_level=1 auth_mode=optional" \
            "$O_CLI -key data_files/server2.key \
             -cert data_files/server2.ku-ds.crt" \
            0 \
            -S "bad certificate (usage extensions)" \
            -S "Processing of the Certificate handshake message failed"

run_test    "keyUsage cli-auth: RSA, KeyEncipherment: fail (soft)" \
            "$P_SRV debug_level=1 auth_mode=optional" \
            "$O_CLI -key data_files/server2.key \
             -cert data_files/server2.ku-ke.crt" \
            0 \
            -s "bad certificate (usage extensions)" \
            -S "Processing of the Certificate handshake message failed"

run_test    "keyUsage cli-auth: RSA, KeyEncipherment: fail (hard)" \
            "$P_SRV debug_level=1 auth_mode=required" \
            "$O_CLI -key data_files/server2.key \
             -cert data_files/server2.ku-ke.crt" \
            1 \
            -s "bad certificate (usage extensions)" \
            -s "Processing of the Certificate handshake message failed"

run_test    "keyUsage cli-auth: ECDSA, DigitalSignature: OK" \
            "$P_SRV debug_level=1 auth_mode=optional" \
            "$O_CLI -key data_files/server5.key \
             -cert data_files/server5.ku-ds.crt" \
            0 \
            -S "bad certificate (usage extensions)" \
            -S "Processing of the Certificate handshake message failed"

run_test    "keyUsage cli-auth: ECDSA, KeyAgreement: fail (soft)" \
            "$P_SRV debug_level=1 auth_mode=optional" \
            "$O_CLI -key data_files/server5.key \
             -cert data_files/server5.ku-ka.crt" \
            0 \
            -s "bad certificate (usage extensions)" \
            -S "Processing of the Certificate handshake message failed"

# Tests for extendedKeyUsage, part 1: server-side certificate/suite selection

run_test    "extKeyUsage srv: serverAuth -> OK" \
            "$P_SRV key_file=data_files/server5.key \
             crt_file=data_files/server5.eku-srv.crt" \
            "$P_CLI" \
            0

run_test    "extKeyUsage srv: serverAuth,clientAuth -> OK" \
            "$P_SRV key_file=data_files/server5.key \
             crt_file=data_files/server5.eku-srv.crt" \
            "$P_CLI" \
            0

run_test    "extKeyUsage srv: codeSign,anyEKU -> OK" \
            "$P_SRV key_file=data_files/server5.key \
             crt_file=data_files/server5.eku-cs_any.crt" \
            "$P_CLI" \
            0

# add psk to leave an option for client to send SERVERQUIT
run_test    "extKeyUsage srv: codeSign -> fail" \
            "$P_SRV psk=abc123 key_file=data_files/server5.key \
             crt_file=data_files/server5.eku-cli.crt" \
            "$P_CLI psk=badbad" \
            1

# Tests for extendedKeyUsage, part 2: client-side checking of server cert

run_test    "extKeyUsage cli: serverAuth -> OK" \
            "$O_SRV -key data_files/server5.key \
             -cert data_files/server5.eku-srv.crt" \
            "$P_CLI debug_level=1" \
            0 \
            -C "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-"

run_test    "extKeyUsage cli: serverAuth,clientAuth -> OK" \
            "$O_SRV -key data_files/server5.key \
             -cert data_files/server5.eku-srv_cli.crt" \
            "$P_CLI debug_level=1" \
            0 \
            -C "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-"

run_test    "extKeyUsage cli: codeSign,anyEKU -> OK" \
            "$O_SRV -key data_files/server5.key \
             -cert data_files/server5.eku-cs_any.crt" \
            "$P_CLI debug_level=1" \
            0 \
            -C "bad certificate (usage extensions)" \
            -C "Processing of the Certificate handshake message failed" \
            -c "Ciphersuite is TLS-"

run_test    "extKeyUsage cli: codeSign -> fail" \
            "$O_SRV -key data_files/server5.key \
             -cert data_files/server5.eku-cs.crt" \
            "$P_CLI debug_level=1" \
            1 \
            -c "bad certificate (usage extensions)" \
            -c "Processing of the Certificate handshake message failed" \
            -C "Ciphersuite is TLS-"

# Tests for extendedKeyUsage, part 3: server-side checking of client cert

run_test    "extKeyUsage cli-auth: clientAuth -> OK" \
            "$P_SRV debug_level=1 auth_mode=optional" \
            "$O_CLI -key data_files/server5.key \
             -cert data_files/server5.eku-cli.crt" \
            0 \
            -S "bad certificate (usage extensions)" \
            -S "Processing of the Certificate handshake message failed"

run_test    "extKeyUsage cli-auth: serverAuth,clientAuth -> OK" \
            "$P_SRV debug_level=1 auth_mode=optional" \
            "$O_CLI -key data_files/server5.key \
             -cert data_files/server5.eku-srv_cli.crt" \
            0 \
            -S "bad certificate (usage extensions)" \
            -S "Processing of the Certificate handshake message failed"

run_test    "extKeyUsage cli-auth: codeSign,anyEKU -> OK" \
            "$P_SRV debug_level=1 auth_mode=optional" \
            "$O_CLI -key data_files/server5.key \
             -cert data_files/server5.eku-cs_any.crt" \
            0 \
            -S "bad certificate (usage extensions)" \
            -S "Processing of the Certificate handshake message failed"

run_test    "extKeyUsage cli-auth: codeSign -> fail (soft)" \
            "$P_SRV debug_level=1 auth_mode=optional" \
            "$O_CLI -key data_files/server5.key \
             -cert data_files/server5.eku-cs.crt" \
            0 \
            -s "bad certificate (usage extensions)" \
            -S "Processing of the Certificate handshake message failed"

run_test    "extKeyUsage cli-auth: codeSign -> fail (hard)" \
            "$P_SRV debug_level=1 auth_mode=required" \
            "$O_CLI -key data_files/server5.key \
             -cert data_files/server5.eku-cs.crt" \
            1 \
            -s "bad certificate (usage extensions)" \
            -s "Processing of the Certificate handshake message failed"

# Tests for DHM parameters loading

run_test    "DHM parameters: reference" \
            "$P_SRV" \
            "$P_CLI force_ciphersuite=TLS-DHE-RSA-WITH-AES-128-CBC-SHA \
                    debug_level=3" \
            0 \
            -c "value of 'DHM: P ' (2048 bits)" \
            -c "value of 'DHM: G ' (2 bits)"

run_test    "DHM parameters: other parameters" \
            "$P_SRV dhm_file=data_files/dhparams.pem" \
            "$P_CLI force_ciphersuite=TLS-DHE-RSA-WITH-AES-128-CBC-SHA \
                    debug_level=3" \
            0 \
            -c "value of 'DHM: P ' (1024 bits)" \
            -c "value of 'DHM: G ' (2 bits)"

# Tests for PSK callback

run_test    "PSK callback: psk, no callback" \
            "$P_SRV psk=abc123 psk_identity=foo" \
            "$P_CLI force_ciphersuite=TLS-PSK-WITH-AES-128-CBC-SHA \
            psk_identity=foo psk=abc123" \
            0 \
            -S "SSL - None of the common ciphersuites is usable" \
            -S "SSL - Unknown identity received" \
            -S "SSL - Verification of the message MAC failed"

run_test    "PSK callback: no psk, no callback" \
            "$P_SRV" \
            "$P_CLI force_ciphersuite=TLS-PSK-WITH-AES-128-CBC-SHA \
            psk_identity=foo psk=abc123" \
            1 \
            -s "SSL - None of the common ciphersuites is usable" \
            -S "SSL - Unknown identity received" \
            -S "SSL - Verification of the message MAC failed"

run_test    "PSK callback: callback overrides other settings" \
            "$P_SRV psk=abc123 psk_identity=foo psk_list=abc,dead,def,beef" \
            "$P_CLI force_ciphersuite=TLS-PSK-WITH-AES-128-CBC-SHA \
            psk_identity=foo psk=abc123" \
            1 \
            -S "SSL - None of the common ciphersuites is usable" \
            -s "SSL - Unknown identity received" \
            -S "SSL - Verification of the message MAC failed"

run_test    "PSK callback: first id matches" \
            "$P_SRV psk_list=abc,dead,def,beef" \
            "$P_CLI force_ciphersuite=TLS-PSK-WITH-AES-128-CBC-SHA \
            psk_identity=abc psk=dead" \
            0 \
            -S "SSL - None of the common ciphersuites is usable" \
            -S "SSL - Unknown identity received" \
            -S "SSL - Verification of the message MAC failed"

run_test    "PSK callback: second id matches" \
            "$P_SRV psk_list=abc,dead,def,beef" \
            "$P_CLI force_ciphersuite=TLS-PSK-WITH-AES-128-CBC-SHA \
            psk_identity=def psk=beef" \
            0 \
            -S "SSL - None of the common ciphersuites is usable" \
            -S "SSL - Unknown identity received" \
            -S "SSL - Verification of the message MAC failed"

run_test    "PSK callback: no match" \
            "$P_SRV psk_list=abc,dead,def,beef" \
            "$P_CLI force_ciphersuite=TLS-PSK-WITH-AES-128-CBC-SHA \
            psk_identity=ghi psk=beef" \
            1 \
            -S "SSL - None of the common ciphersuites is usable" \
            -s "SSL - Unknown identity received" \
            -S "SSL - Verification of the message MAC failed"

run_test    "PSK callback: wrong key" \
            "$P_SRV psk_list=abc,dead,def,beef" \
            "$P_CLI force_ciphersuite=TLS-PSK-WITH-AES-128-CBC-SHA \
            psk_identity=abc psk=beef" \
            1 \
            -S "SSL - None of the common ciphersuites is usable" \
            -S "SSL - Unknown identity received" \
            -s "SSL - Verification of the message MAC failed"

# Tests for ciphersuites per version

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Per-version suites: SSL3" \
            "$P_SRV min_version=ssl3 version_suites=TLS-RSA-WITH-3DES-EDE-CBC-SHA,TLS-RSA-WITH-RC4-128-SHA,TLS-RSA-WITH-AES-128-CBC-SHA,TLS-RSA-WITH-AES-128-GCM-SHA256" \
            "$P_CLI force_version=ssl3" \
            0 \
            -c "Ciphersuite is TLS-RSA-WITH-3DES-EDE-CBC-SHA"

run_test    "Per-version suites: TLS 1.0" \
            "$P_SRV arc4=1 version_suites=TLS-RSA-WITH-3DES-EDE-CBC-SHA,TLS-RSA-WITH-RC4-128-SHA,TLS-RSA-WITH-AES-128-CBC-SHA,TLS-RSA-WITH-AES-128-GCM-SHA256" \
            "$P_CLI force_version=tls1 arc4=1" \
            0 \
            -c "Ciphersuite is TLS-RSA-WITH-RC4-128-SHA"

run_test    "Per-version suites: TLS 1.1" \
            "$P_SRV version_suites=TLS-RSA-WITH-3DES-EDE-CBC-SHA,TLS-RSA-WITH-RC4-128-SHA,TLS-RSA-WITH-AES-128-CBC-SHA,TLS-RSA-WITH-AES-128-GCM-SHA256" \
            "$P_CLI force_version=tls1_1" \
            0 \
            -c "Ciphersuite is TLS-RSA-WITH-AES-128-CBC-SHA"

run_test    "Per-version suites: TLS 1.2" \
            "$P_SRV version_suites=TLS-RSA-WITH-3DES-EDE-CBC-SHA,TLS-RSA-WITH-RC4-128-SHA,TLS-RSA-WITH-AES-128-CBC-SHA,TLS-RSA-WITH-AES-128-GCM-SHA256" \
            "$P_CLI force_version=tls1_2" \
            0 \
            -c "Ciphersuite is TLS-RSA-WITH-AES-128-GCM-SHA256"

# Tests for ssl_get_bytes_avail()

run_test    "ssl_get_bytes_avail: no extra data" \
            "$P_SRV" \
            "$P_CLI request_size=100" \
            0 \
            -s "Read from client: 100 bytes read$"

run_test    "ssl_get_bytes_avail: extra data" \
            "$P_SRV" \
            "$P_CLI request_size=500" \
            0 \
            -s "Read from client: 500 bytes read (.*+.*)"

# Tests for small packets

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Small packet SSLv3 BlockCipher" \
            "$P_SRV min_version=ssl3" \
            "$P_CLI request_size=1 force_version=ssl3 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Small packet SSLv3 StreamCipher" \
            "$P_SRV min_version=ssl3 arc4=1" \
            "$P_CLI request_size=1 force_version=ssl3 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.0 BlockCipher" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.0 BlockCipher without EtM" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1 etm=0 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.0 BlockCipher truncated MAC" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.0 StreamCipher truncated MAC" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=1 force_version=tls1 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.1 BlockCipher" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_1 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.1 BlockCipher without EtM" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_1 etm=0 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.1 StreamCipher" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=1 force_version=tls1_1 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.1 BlockCipher truncated MAC" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_1 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.1 StreamCipher truncated MAC" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=1 force_version=tls1_1 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.2 BlockCipher" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.2 BlockCipher without EtM" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_2 etm=0 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.2 BlockCipher larger MAC" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_2 \
             force_ciphersuite=TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.2 BlockCipher truncated MAC" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.2 StreamCipher" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=1 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.2 StreamCipher truncated MAC" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=1 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.2 AEAD" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CCM" \
            0 \
            -s "Read from client: 1 bytes read"

run_test    "Small packet TLS 1.2 AEAD shorter tag" \
            "$P_SRV" \
            "$P_CLI request_size=1 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CCM-8" \
            0 \
            -s "Read from client: 1 bytes read"

# A test for extensions in SSLv3

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "SSLv3 with extensions, server side" \
            "$P_SRV min_version=ssl3 debug_level=3" \
            "$P_CLI force_version=ssl3 tickets=1 max_frag_len=4096 alpn=abc,1234" \
            0 \
            -S "dumping 'client hello extensions'" \
            -S "server hello, total extension length:"

# Test for large packets

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Large packet SSLv3 BlockCipher" \
            "$P_SRV min_version=ssl3" \
            "$P_CLI request_size=16384 force_version=ssl3 recsplit=0 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 16384 bytes read"

requires_config_enabled POLARSSL_SSL_PROTO_SSL3
run_test    "Large packet SSLv3 StreamCipher" \
            "$P_SRV min_version=ssl3 arc4=1" \
            "$P_CLI request_size=16384 force_version=ssl3 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.0 BlockCipher" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1 recsplit=0 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.0 BlockCipher truncated MAC" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1 recsplit=0 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.0 StreamCipher truncated MAC" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=16384 force_version=tls1 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.1 BlockCipher" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1_1 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.1 StreamCipher" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=16384 force_version=tls1_1 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.1 BlockCipher truncated MAC" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1_1 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.1 StreamCipher truncated MAC" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=16384 force_version=tls1_1 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.2 BlockCipher" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.2 BlockCipher larger MAC" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1_2 \
             force_ciphersuite=TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.2 BlockCipher truncated MAC" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CBC-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.2 StreamCipher" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=16384 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.2 StreamCipher truncated MAC" \
            "$P_SRV arc4=1" \
            "$P_CLI request_size=16384 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-RC4-128-SHA \
             trunc_hmac=1" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.2 AEAD" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CCM" \
            0 \
            -s "Read from client: 16384 bytes read"

run_test    "Large packet TLS 1.2 AEAD shorter tag" \
            "$P_SRV" \
            "$P_CLI request_size=16384 force_version=tls1_2 \
             force_ciphersuite=TLS-RSA-WITH-AES-256-CCM-8" \
            0 \
            -s "Read from client: 16384 bytes read"

# Final report

echo "------------------------------------------------------------------------"

if [ $FAILS = 0 ]; then
    printf "PASSED"
else
    printf "FAILED"
fi
PASSES=$(( $TESTS - $FAILS ))
echo " ($PASSES / $TESTS tests ($SKIPS skipped))"

exit $FAILS
