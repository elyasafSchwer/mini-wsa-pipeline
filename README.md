# MiniWSA — Web Security Analytics

A Spring Boot 3 (Java 21) service that ingests web-security events, enriches them
(attack-type classification, threat scoring, per-IP rate-limit / repeat-offender
detection), stores them in Elasticsearch, and exposes analytics APIs. Redis backs the
sliding-window rate tracker.

**Tech stack:** Java 21 · Spring Boot 3.3 · Elasticsearch 8.x · Redis 7 · Maven · Docker.

---

## Architecture at a glance

```
                 ┌──────────────┐   Spring event bus (async)   ┌──────────────┐
POST /v1/events →│  Ingestion   │ ───────────────────────────→ │  Enrichment  │
  /ingest        │  (validate)  │                              │  + scoring   │
                 └──────────────┘                              └─┬─────────┬──┘
                                                                 │    ▲    │
                              repeat-offender window counts      │    │    │  write enriched
                          ┌──────────────┐◄───────────────────── ┘    │    │  document
                          │    Redis     │────────────────────────────     ▼
                          │  rate track  │                        ┌──────────────┐
                          └──────────────┘                        │ Elasticsearch│
                                                                  │  (storage)   │
                                                                  └──────┬───────┘
                                                                         │
                                             GET /v1/stats/summary ──────┤
                                             GET /v1/stats/timeseries ───┘
```

The **Enrichment Service** is the only component that talks to Redis: it reads and updates
the per-IP sliding-window counts there (state/counting for repeat-offender detection), then
writes the **final enriched document** — attack type, threat score, and the resolved
`repeatOffender` flag — to **Elasticsearch**. Elasticsearch and Redis never communicate with
each other; the read APIs (`/v1/stats/*`, `/v1/events/samples`) query Elasticsearch only.

### Key endpoints

| Method & path | Purpose |
|---|---|
| `POST /v1/events/ingest` | Ingest one event or an array of events (all-or-nothing validation). |
| `GET /v1/events/samples` | Individual enriched event records matching filters, paginated (newest first). |
| `GET /v1/stats/summary` | Aggregated stats (counts by category/action, top attackers/paths, avg threat score). |
| `GET /v1/stats/timeseries` | Event counts bucketed by `1m` / `5m` / `1h` for charting. |
| `POST /api/dev/generate` | **`dev` profile only** — generate + ingest simulated attack data. |
| `POST /api/dev/clear` | **`dev` profile only** — delete all events from the index. |
| `POST /api/dev/upload` | **`dev` profile only** — upload a JSON or CSV file and ingest its events. |

---

## 1. Running the Full Stack (Docker)

Brings up **Elasticsearch, Redis, and the app** together. Docker builds the app image
from the multi-stage `Dockerfile` (Maven build → slim JRE runtime), so you need nothing
installed but Docker itself — no local JDK or Maven required.

```bash
docker compose up -d --build
```

- The app starts on **http://localhost:8080**.
- It waits for Elasticsearch and Redis to be *healthy* before booting (`depends_on` +
  health checks), avoiding start-up races.
- Inside the Docker network the app reaches the databases by service name
  (`http://elasticsearch:9200`, `redis:6379`); these are injected as environment
  variables in `docker-compose.yml`.

Check status and logs:

```bash
docker compose ps
docker compose logs -f wsa-app
```

Tear everything down:

```bash
docker compose down
```

> Note: no volumes are mounted, so `docker compose down` discards the Elasticsearch and
> Redis data. This is intentional for a clean review environment.

---

## 2. Local Development (IDE / IntelliJ)

For day-to-day development you run **only the databases** in Docker and run the Spring
Boot app directly from your IDE (so you get hot reload, breakpoints, and debugging).

Start just the databases:

```bash
docker compose up -d redis elasticsearch
```

Then run the app from IntelliJ (or the CLI):

- **IntelliJ:** run `com.es.wsa.MiniWsaApplication` (right-click → Run / Debug).
- **CLI:** `./mvnw spring-boot:run`

No extra configuration is needed. The published ports (`9200`, `6379`) expose the
databases on `localhost`, and `application.yml` defaults to `localhost` when the
Docker-network environment variables are absent:

```yaml
elasticsearch.uris: ${ELASTICSEARCH_URIS:http://localhost:9200}
data.redis.host:    ${REDIS_HOST:localhost}
```

So the same config works both in Docker (env vars set) and on the host (defaults used).

### Running the tests

```bash
./mvnw test
```

Unit and web-slice tests run with no external dependencies. The Elasticsearch
integration test (`StatsAggregationIT`) is **self-skipping**: it runs only when ES is
reachable on `localhost:9200`, otherwise it is skipped (never failed). To run it, start
Elasticsearch first (`docker compose up -d elasticsearch`).

### Running the UI

A companion single-page UI visualizes the analytics APIs (summary charts, time series, and
the repeat-offender drill-down). It is a separate repository. **Run it in the background**
(in its own terminal) alongside the backend:

```bash
git clone https://github.com/elyasafSchwer/mini-wsa-ui.git
cd mini-wsa-ui
npm install
npm run dev
```

The UI will be available at **http://localhost:5173/**. It talks to the backend on
`http://localhost:8080`, so make sure the app (and its databases) are running first.

---

## 3. Data Simulation (Attack Waves)

The project ships an in-memory data-generation pipeline for producing realistic traffic,
including clustered **attack waves** (one IP hammering one path/category, sized to trip the
repeat-offender bonus).

### Architecture

```
SecurityEventGenerator ──list of events──► IngestionFeeder ──HTTP batches──► POST /v1/events/ingest
   (attack profile)                          (batches of 50)                     (real pipeline)
```

- **`SecurityEventGenerator`** — a plain Java class that builds realistic
  `SecurityEvent`s from an `AttackProfile` (total count, attack-wave ratio, wave size,
  RNG seed). Events are emitted in event-time order.
- **`IngestionFeeder`** — a plain Java class that POSTs the events to the ingestion API in
  **batches of 50** over real HTTP (JDK `HttpClient`).
- **`DevDataGenController`** — the only Spring-managed piece. It wires the generator and
  feeder together and triggers the whole flow **server-to-server** in one call, exercising
  the genuine ingestion → enrichment → storage path.

### The `dev` profile gate

The simulator endpoint is **only available when the `dev` Spring profile is active**. The
`DevDataGenController` bean is annotated `@Profile("dev")`, so in any other environment the
route simply does not exist (returns `404`). This keeps the data generator off the
production API surface.

Activate the `dev` profile when starting the app:

**Docker (full stack):** set the profile via environment variable in your shell before
bringing the stack up, or add it to the `wsa-app` service environment:

```bash
# Option A: per-run override
SPRING_PROFILES_ACTIVE=dev docker compose up -d --build
```

**Local (IDE):** add `dev` to the active profiles.

```bash
# CLI
./mvnw spring-boot:run -Dspring-boot.run.profiles=dev
```

- **IntelliJ:** Run/Debug Configuration → *Active profiles* → `dev`
  (or *VM options* → `-Dspring.profiles.active=dev`).

---

## 4. Triggering the Simulator

With the app running under the `dev` profile, trigger a simulation with a single call. The
endpoint generates events in memory and feeds them to the ingestion API in batches, then
returns a summary.

```
POST /api/dev/generate
```

**Query parameters** (all optional):

| Param | Type | Default | Description |
|---|---|---|---|
| `count` | int | profile default (10,000) | total events to generate |
| `seed` | long | random | RNG seed for a reproducible dataset |
| `waveRatio` | double | profile default (0.30) | fraction of events belonging to attack waves, `[0.0, 1.0]` |

### Example

```bash
curl -X POST "http://localhost:8080/api/dev/generate?count=2000&seed=42&waveRatio=0.3"
```

**Sample response:**

```json
{
  "generated": 2000,
  "feed": {
    "totalEvents": 2000,
    "batchesSent": 40,
    "batchesFailed": 0,
    "accepted": 2000
  }
}
```

`batchesSent` reflects the batches-of-50 delivery (2000 ÷ 50 = 40).

### Clearing the index

Delete every document from the `security-events` index in one call:

```bash
curl -X POST "http://localhost:8080/api/dev/clear"
```

**Sample response:**

```json
{ "deleted": 2000 }
```

### Uploading an event file

Feed a locally-produced JSON or CSV file straight into the ingestion pipeline. The format
is auto-detected from the filename extension (`.json` or `.csv`). The same
`events.json` / `events.csv` files in the `data/` directory work directly.

```bash
# JSON
curl -X POST "http://localhost:8080/api/dev/upload" \
     -F "file=@data/events.json"

# CSV
curl -X POST "http://localhost:8080/api/dev/upload" \
     -F "file=@data/events.csv"
```

**Sample response** (same shape as `/generate`):

```json
{
  "generated": 500,
  "feed": {
    "totalEvents": 500,
    "batchesSent": 10,
    "batchesFailed": 0,
    "accepted": 500
  }
}
```

### Verify the ingested data

```bash
# Aggregate summary
curl -s "http://localhost:8080/v1/stats/summary" | jq

# Timeline (hourly buckets) — from/to are required; interval is 1m|5m|1h
curl -s "http://localhost:8080/v1/stats/timeseries?from=2026-07-22T00:00:00Z&to=2026-07-23T00:00:00Z&interval=1h" | jq
```

> Generated events use event timestamps spread across the profile's time span (default:
> the last 24 hours), **not** the wall-clock moment you triggered the run. Query
> `GET /v1/stats/timeseries` (or `_search` in Elasticsearch) to find the actual event-time
> window if you need exact bounds.

---

## 5. Querying Individual Events (Samples API)

While `/v1/stats/*` returns *aggregates*, the Samples API returns the *individual enriched
event records* behind them — useful for drilling into what actually matched a filter.

```
GET /v1/events/samples
```

Results are sorted by event **`timestamp` descending (newest first)** and paginated. The
response includes a `total` count of matching events (independent of paging) so a client
can compute the number of pages.

**Query parameters** (all filters optional):

| Param | Type | Default | Description |
|---|---|---|---|
| `configId` | long | — | restrict to one configuration |
| `clientIp` | string | — | restrict to one client IP (exact address; also accepts CIDR, e.g. `203.0.113.0/24`) |
| `from` | ISO-8601 | — | inclusive lower bound on event `timestamp` |
| `to` | ISO-8601 | — | inclusive upper bound on event `timestamp` |
| `category` | string | — | attack category, e.g. `INJECTION`, `XSS`, `BOT` (case-insensitive) |
| `action` | string | — | enforcement action: `DENY`, `ALERT`, `MONITOR` (case-insensitive) |
| `repeatOffender` | boolean | — | `true`/`false` — restrict to events (not) flagged as repeat offenders |
| `limit` | int | `20` | page size, **max 100** (values above 100 are clamped) |
| `offset` | int | `0` | number of records to skip (pagination) |

Invalid input (malformed/inverted date range, negative `offset`, `limit < 1`) returns
`400` with a `{ "message": ... }` body.

### Examples

```bash
# Newest 20 events (defaults)
curl -s "http://localhost:8080/v1/events/samples" | jq

# Filter: blocked SQL-injection events for one config, second page of 50
curl -s "http://localhost:8080/v1/events/samples?configId=14227&category=INJECTION&action=DENY&limit=50&offset=50" | jq

# Filter: all events from a single attacker IP
curl -s "http://localhost:8080/v1/events/samples?clientIp=203.0.113.42" | jq

# Filter: only repeat-offender events (tripped the rate-limit / +15 bonus)
curl -s "http://localhost:8080/v1/events/samples?repeatOffender=true" | jq
```

**Sample response:**

```json
{
  "total": 1523,
  "limit": 50,
  "offset": 50,
  "items": [
    {
      "eventId": "evt-...",
      "timestamp": "2026-07-23T06:37:18Z",
      "configId": 14227,
      "clientIp": "203.0.113.42",
      "path": "/api/v1/login",
      "method": "POST",
      "statusCode": 403,
      "ruleCategory": "INJECTION",
      "ruleSeverity": "CRITICAL",
      "ruleAction": "DENY",
      "attackType": "SQL/Command Injection",
      "threatScore": 95,
      "repeatOffender": true,
      "geoCountry": "US",
      "receivedAt": "2026-07-23T19:54:34.260+03:00"
    }
  ]
}
```

---

## 6. Data Integrity & Verification

The enrichment output (threat score + repeat-offender flag) is deterministic, so it can be
independently verified — both interactively through the UI and directly against Elasticsearch.

### Manual verification via the UI

The sliding-window rule is: an IP becomes a **repeat offender once its event count within a
10-minute window exceeds the threshold of 5** — i.e. the **6th** event from the same IP
inside that window is the first to be flagged. To confirm it visually:

1. Ingest a dataset (e.g. `POST /api/dev/generate`, or upload `data/events.csv`).
2. In the UI, filter the events for a single busy client IP.
3. Walk its events in chronological order and verify that **the 6th event from that IP
   within a 10-minute window is correctly flagged as a `repeatOffender`** (and that events
   1–5 are not), and that the `+15` repeat-offender bonus is reflected in the threat score.

### Backend integrity check

This query proves the stored data is internally consistent: it uses Elasticsearch
**`runtime_mappings`** to recompute the `threatScore` on the fly from each document's own
fields (severity + action base scores, `+15` sensitive-path bonus, `+15` repeat-offender
bonus, capped at 100), then filters for any document where the freshly recomputed score does
**not** match the stored `threatScore`. A healthy index returns **zero hits** — every stored
score reproduces exactly from its inputs.

```bash
curl --location --request GET 'http://localhost:9200/security-events/_search' \
--header 'Content-Type: application/json' \
--data '{
  "runtime_mappings": {
    "recomputedThreatScore": {
      "type": "long",
      "script": {
        "source": "int score = 0; String sev = doc['\''ruleSeverity'\''].size() > 0 ? doc['\''ruleSeverity'\''].value : '\'''\''; if (sev == '\''CRITICAL'\'') score += 40; else if (sev == '\''HIGH'\'') score += 30; else if (sev == '\''MEDIUM'\'') score += 20; else if (sev == '\''LOW'\'') score += 10; String act = doc['\''ruleAction'\''].size() > 0 ? doc['\''ruleAction'\''].value : '\'''\''; if (act == '\''DENY'\'') score += 20; else if (act == '\''ALERT'\'') score += 10; String p = doc['\''path.keyword'\''].size() > 0 ? doc['\''path.keyword'\''].value.toLowerCase() : '\'''\''; if (p.contains('\''/admin'\'') || p.contains('\''/login'\'')) score += 15; if (doc['\''repeatOffender'\''].size() > 0 && doc['\''repeatOffender'\''].value) score += 15; if (score > 100) score = 100; emit(score);"
      }
    }
  },
  "query": {
    "bool": {
      "filter": {
        "script": {
          "script": { "source": "doc['\''threatScore'\''].value != doc['\''recomputedThreatScore'\''].value" }
        }
      }
    }
  },
  "_source": ["eventId", "clientIp", "path", "ruleSeverity", "ruleAction", "threatScore", "repeatOffender"],
  "fields": ["recomputedThreatScore"],
  "size": 100
}'
```

> The recompute script mirrors the scoring weights in `wsa-policies.yml`. If you tune those
> weights, update the script accordingly (or expect it to surface the difference — which is
> exactly the point of the check).

The same invariant is enforced automatically in CI by the golden-master regression test
(`RepeatOffenderGoldenMasterTest`), which ingests `data/events.csv` and asserts every stored
event matches a checked-in expected-output snapshot field by field.

---

## Configuration reference

Infrastructure connection settings (overridable via environment variables):

| Property | Env var | Default |
|---|---|---|
| Elasticsearch URI | `ELASTICSEARCH_URIS` | `http://localhost:9200` |
| Redis host | `REDIS_HOST` | `localhost` |
| Redis port | `REDIS_PORT` | `6379` |

Business policy (attack categories, threat-scoring weights, rate-limit window/threshold)
lives in `src/main/resources/wsa-policies.yml` and is tunable without a code change.

---

## Production Readiness / Next Steps

MiniWSA is intentionally a single deployable for reviewability. The roadmap below outlines how
it would scale out to a production, high-throughput deployment:

- **Microservices split** — decouple the monolith into 3 independently deployable and scalable
  services: **Ingestion**, **Enrichment**, and **Query/Read**. Each scales on its own load
  profile (ingest spikes, enrichment CPU, read fan-out).

- **Event streaming** — replace the internal in-memory queues (the per-IP `KeyedExecutor`
  lanes) with a **Kafka topic**, partitioned by client IP. This preserves the current per-IP
  ordering guarantee across a cluster and provides durability, back-pressure, and replay.

- **Localized in-memory caching** *(optional but recommended)* — exploit the Kafka
  partition-by-IP layout to hold the IP rate-tracker state **in-memory within the specific pod
  handling that partition**, removing the Redis round-trip from the hot path. When a pod meets
  an unrecognized IP (e.g. after a rebalance), it falls back to checking Elasticsearch first to
  rehydrate that IP's recent history.

- **Tenant-aware tracking** — change the rate-tracker state key from just `ip` to
  `configId + ip → [timestamps]`, so per-IP windows are scoped per tenant/configuration rather
  than shared globally.

- **Logic refinement** — exclude events triggered by `RATE_LIMITER` from receiving the
  `repeatOffender` score bonus (avoid double-counting rate-limit signals as repeat offenses).

- **Dynamic scoring** — allow different score weights per `configId`, so each configuration can
  tune the contribution of specific attributes to the threat score.
