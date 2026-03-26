# PropChain Structured Logging Guide

## Overview

PropChain uses ink! events as the primary structured logging mechanism for on-chain
contracts. Events are emitted during state-changing operations, providing an immutable
audit trail that off-chain indexers and monitoring tools can consume.

This document covers the logging architecture, event conventions, log levels, filtering
strategies, and the log analysis tooling.

## Architecture

```
Contract (on-chain)          Off-chain
+---------------------+     +-------------------------+
| #[ink(event)]       | --> | Substrate event listener |
| struct EventName {  |     | (subxt / polkadot.js)   |
|   #[ink(topic)] id  |     +------------+------------+
|   field: Type       |                  |
| }                   |                  v
+---------------------+     +-------------------------+
                            | log-analyzer.sh         |
                            | (filter, aggregate,     |
                            |  analyze)               |
                            +-------------------------+
```

### Event Flow

1. Contract function executes a state change.
2. `self.env().emit_event(EventName { ... })` writes the event to the block.
3. Off-chain listeners subscribe to contract events via RPC.
4. Events are decoded, filtered by topic, and stored or displayed.

## Event Conventions

### Naming

All events use PascalCase and describe the action that occurred:

- `PropertyRegistered` - not `RegisterProperty`
- `EscrowReleased` - not `ReleaseEscrow`
- `AdminChanged` - not `ChangeAdmin`

### Indexed Fields (Topics)

Use `#[ink(topic)]` on fields that consumers will filter by. ink! allows up to
four topics per event. Prioritize:

1. Entity IDs (property_id, escrow_id, market_id)
2. Account addresses (owner, caller, recipient)
3. Operation types or status codes

### Standard Fields

Every event should include contextual fields where applicable:

| Field | Type | Purpose |
|-------|------|---------|
| `timestamp` | `u64` | Block timestamp via `self.env().block_timestamp()` |
| `block_number` | `u32` | Block number via `self.env().block_number()` |
| `caller` | `AccountId` | Transaction initiator via `self.env().caller()` |

### Example Event Definition

```rust
#[ink(event)]
pub struct PropertyRegistered {
    #[ink(topic)]
    property_id: u64,
    #[ink(topic)]
    owner: AccountId,
    location: String,
    valuation: u128,
    timestamp: u64,
    block_number: u32,
}
```

## Log Levels via Event Categories

Since ink! contracts cannot use traditional log levels (debug, info, warn, error),
PropChain classifies events into severity categories by naming convention:

| Category | Prefix/Pattern | Description | Examples |
|----------|---------------|-------------|----------|
| **Lifecycle** | `*Created`, `*Initialized` | Resource creation | `PropertyRegistered`, `EscrowCreated` |
| **State Change** | `*Updated`, `*Changed`, `*Transferred` | Mutations | `PropertyTransferred`, `MetadataUpdated` |
| **Authorization** | `*Granted`, `*Revoked`, `*Approved` | Permission changes | `ApprovalGranted`, `ApprovalCleared` |
| **Financial** | `*Released`, `*Refunded`, `*Deposited` | Value movements | `EscrowReleased`, `EscrowRefunded` |
| **Administrative** | `*Paused`, `*Resumed`, `Admin*` | System operations | `ContractPaused`, `AdminChanged` |
| **Audit** | `Audit*`, `Compliance*` | Regulatory trail | `AuditLogCreated`, `ComplianceCheckPerformed` |
| **Error/Alert** | `*Failed`, `*Expired`, `*Rejected` | Failure conditions | `DataRetentionExpired` |

### Filtering by Category

Off-chain consumers can filter events by matching event name patterns. The
`scripts/log-analyzer.sh` tool supports category-based filtering:

```bash
# Show only financial events
./scripts/log-analyzer.sh --category financial --input events.json

# Show authorization and admin events (security audit)
./scripts/log-analyzer.sh --category authorization,administrative --input events.json
```

## Contract Event Coverage

All PropChain contracts emit structured events. Current coverage by contract:

| Contract | Event Types | Emit Calls | Key Events |
|----------|------------|------------|------------|
| property-registry (lib) | 26 | 26 | PropertyRegistered, PropertyTransferred, EscrowCreated |
| property-token | 25 | 28 | TokenMinted, TokenTransferred, BridgeLockCreated |
| escrow | 12 | 12 | EscrowCreated, EscrowReleased, MilestoneCompleted |
| insurance | 11 | 11 | PolicyCreated, ClaimFiled, ClaimApproved |
| compliance-registry | 7 | 9 | VerificationUpdated, ComplianceCheckPerformed |
| property-management | 9 | 11 | MaintenanceScheduled, TenantAdded |
| ipfs-metadata | 7 | 7 | MetadataStored, MetadataVerified |
| zk-compliance | 6 | 8 | ProofSubmitted, ProofVerified |
| fees | 5 | 7 | FeeCalculated, FeeConfigUpdated |
| bridge | 5 | 4 | BridgeLockCreated, BridgeTransferCompleted |
| prediction-market | 5 | 5 | MarketCreated, PredictionStaked |
| ai-valuation | 5 | 5 | ValuationRequested, ValuationCompleted |
| oracle | 3 | 3 | PriceUpdated, SourceRegistered |
| proxy | 2 | 2 | Upgraded, AdminChanged |

## Emitting Events in New Code

When adding a new contract function that modifies state, always emit an event:

```rust
#[ink(message)]
pub fn transfer_property(
    &mut self,
    property_id: u64,
    to: AccountId,
) -> Result<(), Error> {
    let caller = self.env().caller();
    // ... validation and state change ...

    self.env().emit_event(PropertyTransferred {
        property_id,
        from: caller,
        to,
        timestamp: self.env().block_timestamp(),
        block_number: self.env().block_number(),
    });

    Ok(())
}
```

### Checklist for Event Emission

- [ ] Every state-changing `#[ink(message)]` emits at least one event.
- [ ] Entity IDs and account addresses are marked with `#[ink(topic)]`.
- [ ] Timestamp and block number are included for time-series analysis.
- [ ] Event name follows the past-tense naming convention.
- [ ] No sensitive data (private keys, raw PII) appears in event fields.

## Log Aggregation

### Subscribing to Events

Using `subxt` (Rust):

```rust
let events = api
    .events()
    .at_latest()
    .await?;

for event in events.iter() {
    let event = event?;
    println!("{:?}", event);
}
```

Using `polkadot.js`:

```javascript
const unsub = await api.query.system.events((events) => {
  events.forEach(({ event }) => {
    if (api.events.contracts.ContractEmitted.is(event)) {
      const [contractAddress, data] = event.data;
      // Decode and store the event
    }
  });
});
```

### Export Format

Events should be exported as newline-delimited JSON (NDJSON) for analysis:

```json
{"event":"PropertyRegistered","property_id":1,"owner":"5GrwvaEF...","timestamp":1700000000,"block":100}
{"event":"PropertyTransferred","property_id":1,"from":"5GrwvaEF...","to":"5FHneW46...","timestamp":1700001000,"block":105}
```

## Log Analysis

The `scripts/log-analyzer.sh` script provides filtering, aggregation, and summary
capabilities for exported event logs. See the script header for full usage.

### Quick Start

```bash
# Summary of all events
./scripts/log-analyzer.sh --input events.json

# Filter by contract
./scripts/log-analyzer.sh --input events.json --contract property-registry

# Filter by event type
./scripts/log-analyzer.sh --input events.json --event PropertyTransferred

# Filter by time range
./scripts/log-analyzer.sh --input events.json --after 1700000000 --before 1700100000

# Filter by account
./scripts/log-analyzer.sh --input events.json --account 5GrwvaEF

# Category-based filtering
./scripts/log-analyzer.sh --input events.json --category financial

# Top events by frequency
./scripts/log-analyzer.sh --input events.json --top 10

# Output as CSV
./scripts/log-analyzer.sh --input events.json --format csv
```

## Troubleshooting

### Events Not Appearing

1. Verify the function completed successfully (did not revert).
2. Check that `self.env().emit_event()` is called after state changes, not before.
3. Confirm the event struct derives `scale::Encode` (automatic with `#[ink(event)]`).

### Missing Topics in Queries

1. Ensure `#[ink(topic)]` is on the field you are filtering by.
2. Topic values are hashed. Use the exact value, not a substring.
3. ink! supports a maximum of four topics per event.

### Large Event Payloads

Avoid storing large strings (full documents, base64 blobs) in events. Use IPFS
content hashes or storage references instead. The `ipfs-metadata` contract
demonstrates this pattern.
