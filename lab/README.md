# Validation lab

Run the isolated target stack with:

```bash
docker compose -f lab/docker-compose.yml up --build
```

Endpoints:

- `http://localhost:8081`
- `https://localhost:8443`

Use `lab/targets.json` as the truth matrix for expected scanner results.

For a broader scanner-by-scanner validation map, see `lab/full-coverage.json`.
