# Deployment Guide

This guide covers the deployment process for PropChain smart contracts across different networks and environments.

## Prerequisites

- Rust and cargo-contract installed
- Substrate node (for local deployment)
- Account with sufficient funds (for testnet/mainnet deployment)
- Network-specific configuration

## Build Process

### Development Build

```bash
# Build in debug mode
cargo contract build

# Build with verbose output
cargo contract build --verbose
```

### Production Build

```bash
# Build optimized contract
cargo contract build --release

# Verify build artifacts
ls -la target/ink/
```

## Local Deployment

### Start Local Node

```bash
# Start a local Substrate node
substrate-node-template --dev --tmp

# Or use a pre-configured node
./scripts/start-local-node.sh
```

### Deploy Contract

```bash
# Instantiate contract
cargo contract instantiate \
  --constructor new \
  --args "" \
  --suri //Alice \
  --salt $(date +%s)

# Get contract address
cargo contract info
```

## Testnet Deployment

### Network Configuration

#### Westend Testnet

```bash
# Set environment variables
export NETWORK=westend
export NODE_URL=wss://westend-rpc.polkadot.io
export SURI=your mnemonic phrase
```

#### Rococo Testnet

```bash
export NETWORK=rococo
export NODE_URL=wss://rococo-rpc.polkadot.io
```

### Deployment Steps

```bash
# 1. Build contract
cargo contract build --release

# 2. Upload contract code
cargo contract upload \
  --url $NODE_URL \
  --suri $SURI

# 3. Instantiate contract
cargo contract instantiate \
  --constructor new \
  --args "" \
  --url $NODE_URL \
  --suri $SURI \
  --salt $(date +%s)
```

## Mainnet Deployment

### Pre-deployment Checklist

- [ ] Contract audited by security firm
- [ ] All tests passing
- [ ] Gas optimization completed
- [ ] Documentation updated
- [ ] Emergency procedures documented
- [ ] Funding allocated for deployment costs

### Deployment Process

```bash
# 1. Final build verification
cargo contract build --release
cargo test --release

# 2. Upload to mainnet
cargo contract upload \
  --url wss://rpc.polkadot.io \
  --suri "$MAINNET_SURI" \
  --confirm

# 3. Instantiate with verification
cargo contract instantiate \
  --constructor new \
  --args "" \
  --url wss://rpc.polkadot.io \
  --suri "$MAINNET_SURI" \
  --confirm \
  --salt $(date +%s)
```

## Network-specific Considerations

### Polkadot

- **Gas Costs**: Higher than testnets
- **Finality**: ~24 seconds
- **Security**: Relay chain security
- **Upgradeability**: Proxy pattern recommended

### Kusama

- **Gas Costs**: Lower than Polkadot
- **Finality**: ~12 seconds
- **Experimental**: Faster feature rollout
- **Risk**: Higher network risk

### Parachains

- **Configuration**: Varies by parachain
- **Gas Model**: May differ from relay chain
- **Security**: Depends on parachain
- **Integration**: May require custom adapters

## Contract Verification

### On-chain Verification

```bash
# Verify contract code matches source
cargo contract verify \
  --contract $CONTRACT_ADDRESS \
  --url $NODE_URL
```

### Source Code Verification

```bash
# Generate build info
cargo contract build --release --output-json > build-info.json

# Compare with deployed version
./scripts/verify-deployment.sh $CONTRACT_ADDRESS build-info.json
```

## Monitoring and Maintenance

### Deployment Monitoring

```bash
# Monitor contract events
./scripts/monitor-contract.sh $CONTRACT_ADDRESS

# Check contract health
./scripts/health-check.sh $CONTRACT_ADDRESS
```

### Upgrade Process

```bash
# 1. Deploy new version
cargo contract upload --new-version

# 2. Migrate to new contract
./scripts/migrate-contract.sh $OLD_ADDRESS $NEW_ADDRESS

# 3. Verify migration
./scripts/verify-migration.sh $NEW_ADDRESS
```

## Troubleshooting

### Common Issues

#### Insufficient Balance

```bash
# Check account balance
./scripts/check-balance.sh $ACCOUNT_ADDRESS

# Transfer funds if needed
./scripts/transfer-funds.sh $ACCOUNT_ADDRESS $AMOUNT
```

#### Gas Limit Exceeded

```bash
# Estimate gas usage
cargo contract estimate-gas \
  --contract $CONTRACT_ADDRESS \
  --method $METHOD_NAME \
  --args "$ARGS"

# Increase gas limit
cargo contract call \
  --contract $CONTRACT_ADDRESS \
  --method $METHOD_NAME \
  --args "$ARGS" \
  --gas-limit 1000000000000
```

#### Transaction Failed

```bash
# Check transaction status
./scripts/check-tx.sh $TRANSACTION_HASH

# Debug with verbose output
cargo contract call \
  --contract $CONTRACT_ADDRESS \
  --method $METHOD_NAME \
  --args "$ARGS" \
  --verbose
```

## Security Best Practices

### Private Key Management

```bash
# Use secure key storage
export SURI=$(pass show polkadot/mainnet/deployer)

# Never log sensitive data
set +x  # Disable command logging
cargo contract instantiate --suri "$SURI"
set -x
```

### Multi-signature Deployment

```bash
# Deploy with multi-sig
./scripts/deploy-multisig.sh \
  --contract $CONTRACT_ADDRESS \
  --threshold 2 \
  --signers $SIGNER1 $SIGNER2 $SIGNER3
```

### Emergency Procedures

```bash
# Emergency pause
./scripts/emergency-pause.sh $CONTRACT_ADDRESS

# Emergency upgrade
./scripts/emergency-upgrade.sh $CONTRACT_ADDRESS $NEW_CODE_HASH
```

## Automated Deployment Pipeline

PropChain uses GitHub Actions for automated deployments. The pipeline is defined in `.github/workflows/deploy.yml`.

### Pipeline Stages

1. **Pre-deployment Tests** - Formatting, linting, and unit tests must pass.
2. **Security Checks** - `cargo audit` scans for known vulnerabilities.
3. **Build** - Release artifacts are compiled and stored.
4. **Deploy** - Contracts are deployed to the target network.
5. **Rollback** - Automatic rollback if deployment fails.
6. **Notification** - Reports deployment status.

### Triggering a Deployment

Deployments are triggered automatically on version tags or manually via workflow dispatch.

```bash
# Tag-based deployment (triggers automatically)
git tag v1.0.0
git push origin v1.0.0

# Manual deployment via GitHub CLI
gh workflow run deploy.yml \
  --field network=westend \
  --field dry_run=false
```

### Deployment Script Usage

The `scripts/deploy.sh` script supports several commands.

```bash
# Deploy all contracts to a network
./scripts/deploy.sh --network westend

# Deploy a specific contract with verification
./scripts/deploy.sh --network westend --contract property-token --verify

# List current deployments
./scripts/deploy.sh --network westend --list

# Rollback to previous deployment state
./scripts/deploy.sh --network westend --rollback

# Skip pre-deployment tests (not recommended for production)
./scripts/deploy.sh --network local --skip-tests
```

## Rollback Mechanisms

### Automatic Rollback

The deployment script backs up the current deployment state before deploying. If deployment fails, it automatically restores the previous state.

Note: On-chain contracts are immutable. Rollback restores local deployment records (addresses, code hashes). If a deployed contract is faulty, redeploy the previous version as a new instance.

### Manual Rollback

```bash
# Rollback to the most recent backup
./scripts/deploy.sh --network westend --rollback

# Rollback to a specific backup
./scripts/deploy.sh --network westend --rollback deployments/backups/westend-20240101-120000
```

### Backup Structure

Backups are stored in `deployments/backups/` with timestamped directories.

```
deployments/
  backups/
    westend-20240101-120000/
      property-token.json
      property-registry.json
    westend-20240115-090000/
      property-token.json
  westend/
    property-token.json
    property-registry.json
```

## Post-deployment

### Documentation Update

- Update contract addresses in documentation
- Add deployment notes to changelog
- Update API documentation if needed
- Notify stakeholders of deployment

### Community Communication

- Announce deployment on Discord/Telegram
- Post deployment summary on GitHub
- Update project status page
- Send notification to subscribers

### Post-deployment Monitoring

The deploy script includes a built-in monitoring step that verifies contract accessibility and reports the on-chain code hash after each deployment.

For ongoing monitoring:

- Verify contract accessibility using `cargo contract info --contract $ADDRESS --url $NODE_URL`
- Track gas usage patterns by reviewing transaction history on block explorers
- Monitor contract events using Substrate event subscriptions
- Set up alerts for failed transactions or unexpected state changes
