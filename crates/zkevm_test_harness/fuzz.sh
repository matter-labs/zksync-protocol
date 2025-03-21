#!/bin/bash

FUZZ_LOGS="./fuzz/fuzz_logs"
FUZZ_ARTIFACTS="./fuzz/artifacts"
FUZZ_CORPUS="./fuzz/corpus"
FUZZ_SEEDS="./fuzz/seeds"

function usage() {
    echo "
Usage: $0 <command> [options]
Commands:
    list                          List existing fuzz targets
    smoke --time=<minutes>        Sequentially run all fuzzers for X minutes (default: 1) without any features
    regression                    Run fuzzer on the test inputs (corpus) without fuzzing
    lint                          Lint fuzz tests
    check                         Check if a crash has occurred
    clean                         Clean fuzz data (artifacts and corpus)
    prepare                       Prepare the system for fuzzing
    corpus                        Generate corpus files from seeds explicitly
    install                       Install dependencies
    run                           Run default fuzz tests
    report                        Make a report
    parallel                      Run fuzz tests in parallel
        --jobs=<number>           Max number of jobs to run in parallel
        --target=<target>         Prefix for fuzz targets to run (default: '*')
        --timeout=<seconds>       Timeout for the fuzz tests (default: 600)
Options:
    -h, --help                    Show this help message
"
    exit 1
}

# Utility function to parse key-value arguments (--key=value)
function parse_args() {
    for arg in "$@"; do
        case $arg in
            --*=*) key=$(echo "$arg" | cut -d '=' -f 1); value=$(echo "$arg" | cut -d '=' -f 2); eval "${key#--}='$value'" ;;
            --*) key=$(echo "$arg" | cut -d '=' -f 1); eval "${key#--}=1" ;;
        esac
    done
}

function run_report() {
  	echo "Sending report to Slack..."
  	if [ -z "$SLACK_WEBHOOK_URL" ]; then
  			echo "Error: SLACK_WEBHOOK_URL is not set. Aborting.";
  			exit 1; \
  	fi

  	commit_hash=$(git rev-parse HEAD)

  	check_output="zksync-protocol fuzzer on $commit_hash: $(check)"
  	if [ -z "$check_output" ]; then
        echo "Error: Check output is empty. Aborting."
        exit 1
    fi

    payload=$(printf '{"text": "%s"}' "$check_output")

    # Send the payload to the Slack webhook
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "$payload" "$SLACK_WEBHOOK_URL")

    if [ "$response" -ne 200 ]; then
        echo "Error: Failed to send report to Slack. HTTP status code: $response"
        exit 1
    fi

    echo "Report successfully sent to Slack."

}

function run_run() {
    echo "Running fuzz tests session with the default settings..."
    clean
    prepare
    echo ""
    run_parallel --jobs="4" --target="precompiles" --timeout="6000"
    echo ""
    run_report
}

function run_parallel() {
    # Make corpus
    corpus

    parse_args "$@"

    # Default argument values
    jobs="${jobs:-4}"
    target="${target:-"*"}"
    timeout="${timeout:-600}"

    echo "Running parallel fuzzing with the following parameters:"
    echo "  Jobs: $jobs"
    echo "  Fuzz targets template: $target"
    echo "  Timeout: $timeout seconds"

    # Match all fuzzing targets if target is '*'
    if [ "$target" = "*" ]; then
        targets=$(cargo fuzz list)
    else
        targets=$(cargo fuzz list | grep -E "^${target}")
    fi

    if [ -z "$targets" ]; then
        echo "No fuzzing targets matching '$target' found!"
        exit 1
    fi

    echo "  Fuzz targets:"
    for target in $targets; do
        echo -e "\t$target"
    done

    mkdir -p "$FUZZ_LOGS"

    memory="-rss_limit_mb=8192"

    cargo fuzz build -D

    parallel -j "$jobs" -v --eta --progress --results "$FUZZ_LOGS" \
        cargo fuzz run -D "{}" -- "$memory" -max_total_time=${timeout} ::: "$targets"
}

function check() {
    if [[ ! -d "$FUZZ_ARTIFACTS" ]]; then
        echo "Error: Output directory '$FUZZ_ARTIFACTS' not found!"
        exit 1
    fi

    CRASH_FILES=$(find "$FUZZ_ARTIFACTS" -type f \( -name "crash-*" -o -name "leak-*" -o -name "timeout-*" \))

    if [[ -n "$CRASH_FILES" ]]; then
        echo "🚨 Crash detected! 🚨"
        echo "$CRASH_FILES"
        exit 1
    else
        echo "✅ No crashes found."
        exit 0
    fi
}

function clean() {
    echo "Cleaning artifacts directory: $FUZZ_ARTIFACTS"
    rm -rf ${FUZZ_ARTIFACTS:?}/*

    echo "Cleaning logs directory: $FUZZ_FUZZ_LOGS"
    rm -rf ${FUZZ_LOGS:?}/*

    echo "Cleaning generated corpus directory: $FUZZ_CORPUS"
    for dir in $FUZZ_CORPUS; do
        echo "Cleaning corpus directory: $dir"
        find "$dir" -type f ! -name "corpus*" -exec rm -v {} +
    done
}

function list() {
    cargo fuzz list
}

function corpus() {
    echo "Creating corpus directories for all fuzz targets..."
    rm -rf $FUZZ_CORPUS

    # Create corpus directories for all fuzz targets
    FUZZ_TARGETS=$(cargo fuzz list)
    for target in $FUZZ_TARGETS; do
        mkdir -p "$FUZZ_CORPUS/$target"
    done

    for seed_dir in $FUZZ_SEEDS/*; do
        if [ -d "$seed_dir" ]; then
            seed_name=$(basename "$seed_dir")

            # Check if the name matches any fuzz target
            if echo "$FUZZ_TARGETS" | grep -q "$seed_name"; then
                cp -v "$seed_dir"/* "$FUZZ_CORPUS/$seed_name/" 2>/dev/null || true
            # else do nothing
            else
                # noop
                :
            fi
        fi
    done
}

function install() {
    cargo install cargo-fuzz
}

function prepare() {
    echo "Nothing to prepare"
}

function lint() {
    cargo fmt
    cargo clippy --workspace -- -D warnings
}

function smoke() {
    # Make corpus
    clean
    prepare
    corpus

    parse_args "$@"
    time="${time:-1}" # Default to 1 minute

    RUN_TIME_SECONDS="$((time * 60))"
    FUZZ_TARGETS=$(cargo fuzz list)

    if [ -z "$FUZZ_TARGETS" ]; then
        echo "No fuzz targets found."
        exit 1
    fi

    for TARGET in $FUZZ_TARGETS; do
        echo "============================================"
        echo "Running fuzz target: $TARGET"
        echo "Duration: $time minute(s)"
        echo "============================================"
        cargo fuzz run -D "$TARGET" -- -max_total_time="$RUN_TIME_SECONDS"
        echo "Finished fuzz target: $TARGET"
        echo "============================================"
    done

    echo ""
    run_report
}

function regression() {
    # Make corpus
    corpus

    echo "Running regression tests on all fuzz targets..."

    # Get the list of fuzz targets
    FUZZ_TARGETS=$(cargo fuzz list)

    if [ -z "$FUZZ_TARGETS" ]; then
        echo "No fuzz targets found."
        exit 1
    fi

    # For each fuzz target, find corresponding corpus files
    for TARGET in $FUZZ_TARGETS; do
        CORPUS_DIR="${FUZZ_CORPUS}/${TARGET}"

        if [[ ! -d "$CORPUS_DIR" ]]; then
            echo "⚠️  No corpus directory found for fuzz target: $TARGET"
            continue
        fi

        # Loop through each file in the corpus directory
        for CORPUS_FILE in "$CORPUS_DIR"/*; do
            # Ensure the file exists before testing
            if [[ ! -f "$CORPUS_FILE" ]]; then
                echo "⚠️  No corpus files found for fuzz target: $TARGET"
                continue
            fi

            echo "============================================"
            echo "Running regression test for target: $TARGET"
            echo "Using corpus file: $CORPUS_FILE"
            echo "============================================"

            # Run the target against the corpus file
            cargo fuzz run -D "$TARGET" "$CORPUS_FILE" -- -rss_limit_mb=8192
        done
    done

    echo "Regression tests completed."
}

# Main script logic
case "$1" in
    "list")
        shift
        list
        ;;
    "corpus")
        shift
        corpus
        ;;
    "lint")
        shift
        lint
        ;;
    "smoke")
        shift
        smoke "$@"
        ;;
    "regression")
        shift
        regression "$@"
        ;;
    "check")
        shift
        check
        ;;
    "clean")
        shift
        clean
        ;;
    "prepare")
        shift
        prepare
        ;;
    "install")
        shift
        install
        ;;
    "parallel")
        shift
        run_parallel "$@"
        ;;
    "run")
        shift
        run_run "$@"
        ;;
    "report")
        shift
        run_report
        ;;
    *)
        usage
        ;;
esac