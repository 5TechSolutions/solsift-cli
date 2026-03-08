# SolSift CLI

Command-line interface for smart contract security auditing powered by SolSift API.

## Installation

### Requirements

- Docker
- solsift-api running and accessible

## Run Modes

Make sure `solsift-api` is running before any command.
Image runtime is Python 3.14 (`python:3.14-slim`).

### 1. CLI locally

```powershell
$env:API_BASE_URL="http://localhost:8000"
python .\cli.py .\test_contracts\BadSmartContract.sol -v -t slither
```

### 2. CLI in Docker

Build:

```powershell
docker build -t solsift-cli -f Dockerfile .
```

Run:

```powershell
docker run --rm `
  -v "${PWD}\test_contracts:/app/test_contracts:ro" `
  --network solsift-api_solsift-network `
  -e API_BASE_URL=http://api:8000 `
  solsift-cli ./test_contracts/BadSmartContract.sol -v -t slither
```

### 3. Tests locally (runner on host, CLI always in Docker)

```powershell
$env:DOCKER_NETWORK="solsift-api_solsift-network"
$env:API_BASE_URL="http://api:8000"

python .\test_contracts\app\test_smart_contracts.py `
  --vulnerable-dir "C:\Users\jakub\Desktop\5TS\Repos\SmartContractAuditing\Vulnerable_SourceCodes" `
  --clean-dir "C:\Users\jakub\Desktop\5TS\Repos\SmartContractAuditing\Secure_SourceCodes" `
  --tools slither,mythril `
  --seed 42 `
  --workers 4 `
  --count 200
```

### 4. Tests in Docker (runner inside container)

Build:

```powershell
docker build -t solsift-tester -f Dockerfile.tester .
```

Run:

```powershell
$base = "C:\Users\jakub\Desktop\5TS\Repos\SmartContractAuditing"
$results = "${PWD}\test_contracts\results"

docker run --rm `
  -v "${base}\Vulnerable_SourceCodes:/data/vulnerable:ro" `
  -v "${base}\Secure_SourceCodes:/data/clean:ro" `
  -v "${results}:/app/test_contracts/results" `
  --network solsift-api_solsift-network `
  -e API_BASE_URL=http://api:8000 `
  solsift-tester `
  --vulnerable-dir /data/vulnerable `
  --clean-dir /data/clean `
  --tools slither,mythril `
  --seed 42 `
  --workers 4 `
  --count 200
```

In this mode, the runner uses local `cli.py` inside the tester container (no nested `docker run`).

Results:
- single JSON file: `test_contracts/results/audit_results_YYYYMMDD_HHMMSS.json`
- contains run parameters, summary, and per-file results (including detecting tools)

## Dataset Source

The larger dataset used for running batch audits with the test app comes from Kaggle:
https://www.kaggle.com/datasets/bcccdatasets/bccc-vulscs-2023

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

If your Dockerized CLI must join a specific network, set `DOCKER_NETWORK`, e.g.:
`DOCKER_NETWORK=solsift-api_solsift-network`

Ensure the API service is running before using the CLI.
