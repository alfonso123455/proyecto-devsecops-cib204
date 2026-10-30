# Copilot instructions for this repository

This repository is a DevSecOps lab for a secure software engineering exercise. The app is intentionally insecure in the `inseguro`/`main` branch so the CI pipeline can catch issues; fixes should aim for a hardened, production-safe state.

## Build, test, and lint commands

Run the stack from the repo root:

```bash
docker compose up -d --build
```

This starts:
- `servidor/` as the Node.js RSA encryption service on port 3000
- `keycloak` via Docker Compose for IAM on port 8080

For the backend service (`servidor/`):

```bash
cd servidor
npm install
npm test
npm run lint
```

Run a single Jest test file:

```bash
cd servidor
npm test -- --runTestsByPath ./cifrado.test.js
```

Run a single test by name when needed:

```bash
cd servidor
npm test -- --runInBand --testNamePattern="descifrar"
```

For the Expo mobile app (`app-movil/`):

```bash
cd app-movil
npm install
npm start
# or
npx expo start --web
```

There is no dedicated frontend lint/test script in `app-movil/package.json`; the main automated validation in this repo is on the backend and CI pipeline.

## High-level architecture

This repo contains two major runtime components:

1. `app-movil/` - Expo/React Native client application.
   - It sends user input to the backend service and displays encrypted/unencrypted results.
   - The mobile app does not perform the cryptography itself; the server does.

2. `servidor/` - Node.js/Express API that provides the RSA encryption service.
   - Main entry point: `servidor/servidor.js`
   - Supporting files include `auth.js`, `config.js`, `db.js`, and `cifrado.js`
   - Endpoints include health checks, public-key delivery, encryption/decryption, and security-demo endpoints that intentionally illustrate vulnerable patterns in the lab.

The runtime topology is:

```text
App móvil (Expo/React Native) -> API de cifrado (Node.js/RSA) -> Keycloak (IAM)
```

The Docker Compose stack wires that together via `docker-compose.yml`, and the CI workflow in `.github/workflows/devsecops.yml` validates SAST, secrets, dependency scanning, container image scanning, and OWASP ZAP baseline checks.

## Key conventions and repo-specific patterns

- This is a lab repository with intentionally vulnerable code in the insecure branch. Treat the vulnerable examples as educational artifacts, not as accepted patterns to preserve.
- Keep security fixes targeted and minimal. The repo's purpose is to harden the service until the pipeline passes, so avoid unrelated refactors.
- The backend is configured via environment variables and module config rather than hard-coded values. Check `docker-compose.yml` and `servidor/config.js` before changing auth or network-related behavior.
- Authentication is controlled through `AUTH_ENABLED` in Docker Compose and via `servidor/auth.js`; do not assume IAM is active unless the environment is configured accordingly.
- When changing API behavior, keep the client/server contract stable (`/cifrar`, `/descifrar`, `/salud`, `/llave`, etc.) unless the task explicitly requires a contract update.
- The service logic is intentionally split into a small set of files; the security-relevant behavior is usually in either `servidor.js` or the helper modules it imports, not spread across the repo.
- Because this is a security lab, look at both runtime code and the CI workflow when troubleshooting failures. The pipeline findings are part of the expected workflow, not noise.

## Helpful working notes

- Before patching a vulnerability, check whether the failing issue is in the app server or in the deployment/configuration layer; the repo intentionally mixes both.
- For backend fixes, prefer secure alternatives to pattern-based issues such as command injection, SQL injection, permissive CORS, and unsafe JWT handling.
- For Docker or deployment changes, verify the relevant settings in `docker-compose.yml` and `servidor/Dockerfile` since the image and runtime posture are part of the security challenge.
