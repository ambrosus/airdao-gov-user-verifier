# AirDAO-Gov-User-Verifier

## Description

### User Verifier

User Verifier service provides an endpoint `/verify` which allows to verify if the response acquired from Fractal by using their user uniqueness check is valid and eligible to mint Human SBT. It responses with an encoded and signed Human SBT request to be used with Human SBT issuer smart contract call `sbtMint`.

### Gov Portal DB

Back-end service which responsive for session token generation and being a middleware between web app and database.

### Gov Portal Mocker

Mocker for Gov Portal web app which allows user to check their uniqueness with Fractal identity system and verify the response with User Verifier service.

## Requirements

Rust toolchain version 1.74

## Configuration

### User Verifier

#### Default configuration

Default configuration could be found in `./config/default.json` file.

- `listenAddress`: host:port to run the verifier service at. Defaults to `localhost:10000`
- `signer`: signer configuration
    - `signingKey`: hex encoded private key to sign Human SBT requests to be used as arguments for Human SBT issuer smart contract call `sbtMint`. Should be set before app start
    - `requestLifetime`: lifetime duration in millis for which the signed request will be valid to use for Human SBT issuer smart contract call `sbtMint`. Defaults to 60 seconds
    - `sbtLifetime`: lifetime duration in millis for Human SBT since minted for a user. Defaults to 100 years
- `fractal`: Fractal Id configuration
    - `requestTokenUrl`: url used to exchange auth code for auth token. Could be found in Fractal Id documentation. Defaults to production env
    - `requestUserUrl`: url used to fetch Fractal user information by auth token. Defaults to production env
    - `clientId`: client id for Fractal integration. Could be found in Admin section at Fractal web app for developers. Should be set before app start
    - `clientSecret`: client secret for Fractal integration. Could be found in Admin section at Fractal web app for developers. Should be set before app start

#### Override configuration

Default configuration and credentials could be overriden by using `./config/custom.json` file.

### Gov Portal DB

#### Default configuration

Default configuration could be found in `./gov-portal-mocker/config/default.json` file.

- `listenAddress`: host:port to run the gov portal database middleware at. Defaults to `localhost:10001`
- `session`: session manager configuration
    - `secret`: secret to generate session tokens. Should be set before app start
    - `duration`: lifetime duration in seconds for which the session token will be valid to access database by using middleware. Defaults to 1 day

#### Override configuration

Default configuration and credentials could be overriden by using `./config/custom.json` file.

### Gov Portal Mocker

#### Default configuration

Default configuration could be found in `./gov-portal-mocker/config/default.json` file.

- `listenAddress`: host:port to run the gov portal web app mocker at. Defaults to `localhost:8080`
- `userDb`: connection settings to AirDAO Gov Portal DB
    - `baseUrl`: base url to connect to database middleware. Defaults to `http://localhost:10001`
- `signer`: signer configuration
    - `url`: base url for User Verifier service. Defaults to `http://localhost:10000`
    - `redirectUri`: redirect url used by Fractal to redirect users back after uniqueness check. Could be found in Admin section at Fractal web app for developers as `Authorization callback URL`. Defaults to `http://localhost:8080/auth`
    - `fractalClientId`: client id for Fractal integration. Could be found in Admin section at Fractal web app for developers. Should be set before app start
- `web`:
    - `pages`: key-value table with templates for mocker web app pages, where key is an endpoint name and value is file where template content located

#### Override configuration

Default configuration and credentials could be overriden by using `./config/custom.json` file.

## Logging

Supported logging levels: `info`, `debug`, `trace`. Defaults to `info` log level. Could be set with `RUST_LOG` env var.

## Run

### User Verifier

While being inside repo root directory run `cargo run`. Could be run with `RUST_LOG` env variable to set logging level, e.g. `RUST_LOG=debug cargo run`.

### Gov Portal DB

While being inside repo root directory run `cargo run --bin airdao-gov-portal-db`. Could be run with `RUST_LOG` env variable to set logging level, e.g. `RUST_LOG=trace cargo run --bin airdao-gov-portal-db`.

### Gov Portal Mocker

While being inside repo root directory run `cargo run --bin airdao-gov-portal-mocker`. Could be run with `RUST_LOG` env variable to set logging level, e.g. `RUST_LOG=trace cargo run --bin airdao-gov-portal-mocker`.

## Usage

Open web browser and go to default url `http://localhost:8080`, or any other url if overriden in Gov Portal Mocker configuration file.
