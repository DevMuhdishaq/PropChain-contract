#!/usr/bin/env bash

# PropChain Log Analyzer
# Parses, filters, and aggregates contract event logs exported as NDJSON.
#
# Usage:
#   ./scripts/log-analyzer.sh --input events.json [OPTIONS]
#
# Options:
#   --input FILE        Input NDJSON file (required)
#   --event NAME        Filter by event name (exact match)
#   --contract NAME     Filter by contract name (substring match)
#   --account ADDR      Filter by account address (substring match across all fields)
#   --category CAT      Filter by event category (comma-separated):
#                        lifecycle, state_change, authorization, financial,
#                        administrative, audit, error
#   --after TIMESTAMP   Show events after this Unix timestamp
#   --before TIMESTAMP  Show events before this Unix timestamp
#   --top N             Show top N events by frequency
#   --format FMT        Output format: json (default), csv, summary
#   --help              Show this help message

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Defaults
INPUT_FILE=""
EVENT_FILTER=""
CONTRACT_FILTER=""
ACCOUNT_FILTER=""
CATEGORY_FILTER=""
AFTER_TS=""
BEFORE_TS=""
TOP_N=""
OUTPUT_FORMAT="json"

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Category patterns for event classification
category_pattern() {
    local category="$1"
    case "$category" in
        lifecycle)
            echo "Created|Initialized|Registered|Minted|Deployed"
            ;;
        state_change)
            echo "Updated|Changed|Transferred|Modified|Set|Completed"
            ;;
        authorization)
            echo "Granted|Revoked|Approved|Cleared|Authorized"
            ;;
        financial)
            echo "Released|Refunded|Deposited|Withdrawn|Paid|Staked|Fee"
            ;;
        administrative)
            echo "Paused|Resumed|Upgraded|Admin|Config|Emergency"
            ;;
        audit)
            echo "Audit|Compliance|Verification|Consent|Retention"
            ;;
        error)
            echo "Failed|Expired|Rejected|Reverted|Error"
            ;;
        *)
            log_error "Unknown category: $category"
            log_error "Valid categories: lifecycle, state_change, authorization, financial, administrative, audit, error"
            exit 1
            ;;
    esac
}

show_help() {
    sed -n '2,/^$/s/^# \?//p' "$0"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input)
            INPUT_FILE="$2"
            shift 2
            ;;
        --event)
            EVENT_FILTER="$2"
            shift 2
            ;;
        --contract)
            CONTRACT_FILTER="$2"
            shift 2
            ;;
        --account)
            ACCOUNT_FILTER="$2"
            shift 2
            ;;
        --category)
            CATEGORY_FILTER="$2"
            shift 2
            ;;
        --after)
            AFTER_TS="$2"
            shift 2
            ;;
        --before)
            BEFORE_TS="$2"
            shift 2
            ;;
        --top)
            TOP_N="$2"
            shift 2
            ;;
        --format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        --help|-h)
            show_help
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information." >&2
            exit 1
            ;;
    esac
done

# Validate input
if [[ -z "$INPUT_FILE" ]]; then
    log_error "No input file specified. Use --input FILE."
    exit 1
fi

if [[ ! -f "$INPUT_FILE" ]]; then
    log_error "Input file not found: $INPUT_FILE"
    exit 1
fi

# Check for jq
if ! command -v jq >/dev/null 2>&1; then
    log_error "jq is required but not installed. Install it with: brew install jq (macOS) or apt install jq (Linux)"
    exit 1
fi

# Validate JSON
if ! jq empty "$INPUT_FILE" 2>/dev/null; then
    log_error "Input file is not valid JSON/NDJSON: $INPUT_FILE"
    exit 1
fi

# Build jq filter chain
JQ_FILTER="."

# Event name filter
if [[ -n "$EVENT_FILTER" ]]; then
    JQ_FILTER="$JQ_FILTER | select(.event == \"$EVENT_FILTER\")"
fi

# Contract filter
if [[ -n "$CONTRACT_FILTER" ]]; then
    JQ_FILTER="$JQ_FILTER | select(.contract // \"\" | test(\"$CONTRACT_FILTER\"; \"i\"))"
fi

# Account filter (search across all string fields)
if [[ -n "$ACCOUNT_FILTER" ]]; then
    JQ_FILTER="$JQ_FILTER | select(tostring | test(\"$ACCOUNT_FILTER\"))"
fi

# Category filter
if [[ -n "$CATEGORY_FILTER" ]]; then
    PATTERN=""
    IFS=',' read -ra CATEGORIES <<< "$CATEGORY_FILTER"
    for cat in "${CATEGORIES[@]}"; do
        cat_pattern=$(category_pattern "$cat")
        if [[ -n "$PATTERN" ]]; then
            PATTERN="$PATTERN|$cat_pattern"
        else
            PATTERN="$cat_pattern"
        fi
    done
    JQ_FILTER="$JQ_FILTER | select(.event | test(\"$PATTERN\"))"
fi

# Timestamp filters
if [[ -n "$AFTER_TS" ]]; then
    JQ_FILTER="$JQ_FILTER | select((.timestamp // 0) >= $AFTER_TS)"
fi

if [[ -n "$BEFORE_TS" ]]; then
    JQ_FILTER="$JQ_FILTER | select((.timestamp // 0) <= $BEFORE_TS)"
fi

# Execute based on output format
case "$OUTPUT_FORMAT" in
    json)
        if [[ -n "$TOP_N" ]]; then
            log_info "Top $TOP_N events by frequency:"
            jq -s "[.[] | $JQ_FILTER] | group_by(.event) | map({event: .[0].event, count: length}) | sort_by(-.count) | .[:$TOP_N]" "$INPUT_FILE"
        else
            jq -c "$JQ_FILTER" "$INPUT_FILE"
        fi
        ;;
    csv)
        log_info "Outputting as CSV..."
        echo "event,timestamp,block_number,account"
        jq -r "[$JQ_FILTER] | . as \$item | \"\(.event // \"\"),\(.timestamp // \"\"),\(.block_number // \"\"),\(.caller // .owner // .from // \"\")\"" "$INPUT_FILE"
        ;;
    summary)
        log_info "Event Log Summary"
        echo ""

        TOTAL=$(jq -s "[.[] | $JQ_FILTER] | length" "$INPUT_FILE")
        echo -e "${CYAN}Total events:${NC} $TOTAL"
        echo ""

        echo -e "${CYAN}Events by type:${NC}"
        jq -s "[.[] | $JQ_FILTER] | group_by(.event) | map({event: .[0].event, count: length}) | sort_by(-.count) | .[] | \"  \(.event): \(.count)\"" -r "$INPUT_FILE"
        echo ""

        echo -e "${CYAN}Events by category:${NC}"
        for cat in lifecycle state_change authorization financial administrative audit error; do
            pattern=$(category_pattern "$cat")
            count=$(jq -s "[.[] | $JQ_FILTER | select(.event | test(\"$pattern\"))] | length" "$INPUT_FILE")
            if [[ "$count" -gt 0 ]]; then
                echo "  $cat: $count"
            fi
        done
        echo ""

        if jq -e '.[0].timestamp // empty' "$INPUT_FILE" >/dev/null 2>&1; then
            FIRST_TS=$(jq -s "[.[] | $JQ_FILTER | .timestamp // 0] | min" "$INPUT_FILE")
            LAST_TS=$(jq -s "[.[] | $JQ_FILTER | .timestamp // 0] | max" "$INPUT_FILE")
            echo -e "${CYAN}Time range:${NC} $FIRST_TS - $LAST_TS"
        fi

        UNIQUE_EVENTS=$(jq -s "[.[] | $JQ_FILTER | .event] | unique | length" "$INPUT_FILE")
        echo -e "${CYAN}Unique event types:${NC} $UNIQUE_EVENTS"
        ;;
    *)
        log_error "Unknown format: $OUTPUT_FORMAT. Use: json, csv, summary"
        exit 1
        ;;
esac
