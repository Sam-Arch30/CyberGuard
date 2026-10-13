# Deployment quickstart

Use Docker Compose 2.24+ on a host with adequate RAM and disk. This configuration is prepared for a single-host deployment; container execution still requires verification.

Create a private `.env.deploy` (ignored by Git). Set these values with newly generated secrets:

```dotenv
POSTGRES_USER=cyberguard
POSTGRES_DB=cyberguard
POSTGRES_PASSWORD=REPLACE_WITH_RANDOM_HEX_SECRET
CYBERGUARD_AUTH_SECRET=REPLACE_WITH_RANDOM_SECRET_AT_LEAST_32_CHARACTERS
CYBERGUARD_SERVER_CREDENTIALS='{"REPLACE_WITH_RANDOM_ACCESS_TOKEN":{"actor_id":"demo-operator","role":"admin","workspaces":["default"]}}'
CORS_ORIGINS=https://YOUR_DOMAIN
VITE_API_BASE_URL=
FRONTEND_PORT=3000
MAX_UPLOAD_SIZE_MB=50
```

Do not use the placeholder credentials. Generate each independently, e.g. `python -c "import secrets; print(secrets.token_hex(32))"`. Do not commit the environment file. Existing local databases and evidence are not copied; Docker creates separate persistent volumes.

```sh
docker compose --env-file .env.deploy -f docker-compose.yml -f docker-compose.prod.yml config --quiet
docker compose --env-file .env.deploy -f docker-compose.yml -f docker-compose.prod.yml up -d --build
docker compose --env-file .env.deploy -f docker-compose.yml -f docker-compose.prod.yml ps
```

Serve port 3000 through an HTTPS reverse proxy before public use. Only the frontend is exposed; PostgreSQL and backend stay internal. Enter the configured access token in the frontend session controls. Optional external intelligence/LLM providers need their own keys. Media decoding tools are included, but trained model weights are not bundled and validated deepfake detection is not claimed. Never delete volumes to update an existing deployment. Back up volumes before upgrades.

Verification boundary: Compose configuration and frontend build are checked separately from actual Docker image builds, PostgreSQL startup, migrations, HTTPS and end-to-end deployed detection. Those runtime checks are required before calling the deployment ready.
