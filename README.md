# SolSift CLI

Command-line interface for smart contract security auditing powered by SolSift API.

## Installation

### Requirements

- Docker
- solsift-api running and accessible

## Usage

Make sure the solsift-api is running first:

```bash
docker run -v /Users/patryk/Desktop/solsift-cli/test_contracts:/app/test_contracts \
  --network solsift-api_solsift-network \
  -e API_BASE_URL=http://api:8000 \
  solsift-cli ./test_contracts/BadSmartContract.sol
```

## Test Contracts

Sample smart contracts are included in `test_contracts/`:

- `BadSmartContract.sol` - Contract with security issues
- `CriticalSmartContract.sol` - Contract with critical vulnerabilities
- `Dao.sol` - DAO contract example
- `Dex-0.4.24.sol` - DEX contract example
- `VulnerableToken.sol` - ERC20 token with vulnerabilities

## Configuration

Set the API base URL using the `API_BASE_URL` environment variable:

```bash
export API_BASE_URL=http://localhost:8000
```

Default: `http://api:8000` (when running with docker-compose)

Ensure the API service is running before using the CLI.
