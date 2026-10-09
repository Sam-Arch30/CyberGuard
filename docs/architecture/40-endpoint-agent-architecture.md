# Section 31 — Endpoint Agent Architecture

## 1. Agent Purpose & Philosophy

The **CYBERGUARD Endpoint Agent** is an authorized, lightweight host observation and telemetry forwarding component. Its core responsibility is to securely collect authorized host security events and transmit normalized telemetry to the existing CYBERGUARD backend (`UniversalIngestionGateway` &rarr; `ThreatEvent` &rarr; `AnalysisOrchestrator` &rarr; `SecurityKnowledgeGraph`).

### Core Design Principle: Thin Agent, Centralized Intelligence

The agent is designed as a **thin, reliable observer**:
* **Endpoint Agent Responsibilities**: `COLLECT`, `NORMALIZE`, `FILTER`, `BUFFER`, `AUTHENTICATE`, `TRANSMIT`, and `HEALTH-REPORT`.
* **Backend Platform Responsibilities**: `CORRELATE`, `ANALYZE`, `DETECT`, `SCORE`, `EXPLAIN`, `INVESTIGATE`, and `RESPOND`.

By centralizing detection algorithms, models, and graph heuristics on the CYBERGUARD backend, detection logic remains centrally versioned, tamper-resistant, auditable, and lightweight on endpoint hosts.

```
+-------------------------------------------------------------+
|                       UNTRUSTED / ENDPOINT                  |
| ┌─────────────────────────────────────────────────────────┐ |
| │ Endpoint Agent                                          │ |
| │   - Platform-Neutral Collector Adapters                 │ |
| │   - Client-Side Deterministic Privacy Filter            │ |
| │   - Bounded Local Event Buffer (Priority Queue)         │ |
| │   - Cryptographic Security Controller                   │ |
| └─────────────────────────┬───────────────────────────────┘ |
|                           │                                 |
+---------------------------┼---------------------------------+
                            │ TLS 1.3 / HMAC-SHA256 Auth
                            v
+-------------------------------------------------------------+
|                   CYBERGUARD INGESTION GATEWAY              |
| ┌─────────────────────────────────────────────────────────┐ |
| │ Ingestion & Edge Controls                               │ |
| │   - Machine Credential & Nonce Verification             │ |
| │   - Server-Side Tenant & Agent Identity Binding         │ |
| │   - Monotonic Deduplication (Agent ID + Seq + UUID)     │ |
| │   - Clock Skew Calculation & Event Timestamp Tracking   │ |
| │   - Bounded Request & Payload Rate Limiting             │ |
| └─────────────────────────┬───────────────────────────────┘ |
+---------------------------┼---------------------------------+
                            │ Normalized Stream
                            v
+-------------------------------------------------------------+
|                      CYBERGUARD CORE PIPELINE               |
| ┌─────────────────────────────────────────────────────────┐ |
| │ ThreatEvent Architecture                                │ |
| │   - Universal Ingestion Gateway                         │ |
| │   - Security Knowledge Graph (Agent -> Device -> Threat)│ |
| │   - Behavioral Baseline & Novelty Detection Engine      │ |
| │   - Threat Memory (Curated Incidents Only)              │ |
| │   - Unified Risk Engine & Explainable AI (XAI)          │ |
| └─────────────────────────────────────────────────────────┘ |
+-------------------------------------------------------------+
```

---

## 2. Strict Security Boundaries & Invariants

The CYBERGUARD Endpoint Agent is strictly governed by non-negotiable security guarantees.

### What the Agent is NOT:
* **NOT a remote shell**
* **NOT a Remote Access Trojan (RAT)**
* **NOT a covert persistence mechanism**
* **NOT an arbitrary command or script executor**
* **NOT a vulnerability scanner or exploitation framework**
* **NOT an autonomous destructive response actor**

The agent operates **only** on systems where the enterprise organization has explicitly deployed and authorized its installation. If an attacker attempts to send command execution instructions to the agent runtime, the client runtime raises a `SecurityViolationException` and rejects the payload.

---

## 3. Trust Boundaries

1. **Endpoint Space (Untrusted / Adversarial)**:
   - The endpoint host OS environment may experience network interruptions, clock drift, compromised local processes, or hostile tampering.
   - Telemetry from the agent is treated by the backend as raw evidence, never as unverified security verdicts.
2. **Transport Boundary**:
   - Telemetry batches and heartbeats travel strictly over TLS 1.3 HTTPS.
   - Plaintext HTTP is forbidden in production environments.
   - Each HTTP request carries cryptographic HMAC-SHA256 signatures binding the request method, path, timestamp, nonce, and payload hash.
3. **Ingestion Gateway (Enforcement Point)**:
   - The backend validates machine identity, checks timestamp freshness within $\pm 300\text{ seconds}$, rejects duplicate nonces, validates schema compatibility, and strictly derives the tenant `workspace_id` from the authenticated credential rather than trusting any client-supplied tenant field.
4. **CYBERGUARD Core (Trusted)**:
   - Canonical `ThreatEventModel`, `DeviceModel`, and `RelationshipModel` entities are created and correlated across the Security Knowledge Graph.

---

## 4. Agent Identity vs. Device Identity

An essential architectural requirement of Section 31 is the strict separation between **Hardware Device Identity** and **Agent Installation Identity**:

| Dimension | `DeviceModel` (`devices`) | `EndpointAgentModel` (`endpoint_agents`) |
| :--- | :--- | :--- |
| **Concept** | Physical or virtual computer hardware host | Installed software runtime instance |
| **Identifier** | Stable hardware UUID / OS machine-id (`device_uid`) | Ephemeral runtime agent UUID (`agent_id`, e.g. `AGT-XXXXXX`) |
| **Lifecycle** | Persists across agent reinstalls, upgrades, or OS resets | Replaced upon reinstallation or software re-provisioning |
| **Relationships** | 1 Device $\rightarrow$ $N$ historical/active Agents | Bound to exactly 1 `DeviceModel` and 1 `workspace_id` |

*Result*: If an agent is uninstalled and reinstalled on the same computer, the backend links the new `EndpointAgentModel` to the existing `DeviceModel`, preserving historical forensic telemetry without creating orphaned hardware records.

---

## 5. Enrollment Lifecycle

CYBERGUARD employs a zero-trust, cryptographically secure enrollment workflow:

```
[Administrator]
       |
       v (POST /api/v1/endpoint/enrollment/tokens)
[Server creates Token: SHA-256 Hash stored, raw secret returned once]
       |
       | (Token delivered to installer out-of-band)
       v
[Agent Installer invokes POST /api/v1/endpoint/enrollment]
       |
       +---> Server verifies Token (hash check, expiration, single-use decrement)
       +---> Resolves/Creates DeviceModel from device_uid
       +---> Creates EndpointAgentModel (status=ACTIVE)
       +---> Issues Machine Credential (key_id + random secret)
       +---> Provisions signed default configuration bundle
       +---> Emits AGENT_ENROLLED immutable audit log
       +---> Graph link created: Agent COLLECTS_FROM Device
       |
       v
[Enrollment Token Exhausted/Invalidated]
```

### Security Controls:
* **Short-lived**: Defaults to 60 minutes validity window.
* **Single-use**: `max_uses=1` (or administratively bounded limit) automatically transitions token status to `EXHAUSTED`.
* **Zero Plaintext Storage**: The server stores only `SHA-256(token)`.
* **Tenant-Scoped**: The token explicitly binds the enrolling agent to the administrative tenant `workspace_id`.

---

## 6. Machine Authentication & Request Signing

Enrolled agents authenticate all server interactions using a machine HMAC-SHA256 signature scheme:

$$\text{Canonical String} = \text{METHOD} + \text{"\n"} + \text{PATH} + \text{"\n"} + \text{TIMESTAMP} + \text{"\n"} + \text{NONCE} + \text{"\n"} + \text{SHA256}(\text{BODY})$$

$$\text{Signature} = \text{HMAC-SHA256}(\text{Credential Secret}, \text{Canonical String})$$

### Request Headers:
* `X-CyberGuard-Agent-ID`: `agent_id`
* `X-CyberGuard-Key-ID`: `key_id`
* `X-CyberGuard-Timestamp`: UNIX timestamp string
* `X-CyberGuard-Nonce`: Random 128-bit hex nonce
* `X-CyberGuard-Signature`: 64-character hex signature
* `Content-Type`: `application/json`

### Replay & Skew Defenses:
1. **Timestamp Window**: Requests with $|T_{\text{server}} - T_{\text{client}}| > 300\text{ s}$ are rejected with `401 Unauthorized`.
2. **Nonce Cache**: The server tracks $(agent\_id, nonce)$ in a bounded in-memory cache to detect and reject replayed messages.
3. **Server-Side Tenant Binding**: The server extracts `workspace_id` from the verified `EndpointAgentModel`. Telemetry payloads cannot override or spoof tenant identity.

---

## 7. Credential Rotation Lifecycle

To prevent long-lived machine secrets from becoming persistent liabilities, the architecture supports seamless in-place credential rotation:

1. Agent submits `POST /api/v1/endpoint/credential/rotate` using its active key.
2. Server verifies the active credential, transitions its status to `ROTATED`, generates a new `key_id` and secret, and commits the record.
3. Server returns `CredentialRotateResponse` with the new machine credential.
4. Agent stages the credential via `stage_rotated_credential()`, tests the new key on its next handshake, and calls `commit_rotated_credential()`.
5. Revoked credentials permanently transition to `REVOKED` and cannot be reactivated.

---

## 8. Versioned & Signed Configuration Management

Agents receive operational policy updates via versioned configuration bundles:

* **Configuration Model**: `EndpointAgentConfigurationModel` (`version`, `batch_size`, `flush_interval_seconds`, `max_buffer_size_events`, `max_buffer_size_bytes`, `enabled_collectors`, `privacy_policy`, `signature`).
* **Cryptographic Signing**: The server signs configuration bundles using HMAC-SHA256 (`SERVER_CONFIG_SIGNING_KEY`).
* **Tamper Verification**: The agent computes the canonical JSON hash of incoming configuration and verifies the signature using `AgentSecurityController.verify_configuration_signature()` before activating changes.
* **Fail-Safe Rollback**: If a new configuration bundle fails signature check or schema validation, the agent rejects the update and continues running with the last-known valid configuration.

---

## 9. Platform-Neutral Collector Architecture

Collectors inherit from the abstract base class `EndpointCollector` and declare explicit capabilities via `CollectorCapability`:

```python
class EndpointCollector(abc.ABC):
    @abc.abstractmethod
    def initialize(self, config: Dict[str, Any]) -> bool: ...
    @abc.abstractmethod
    def start(self) -> bool: ...
    @abc.abstractmethod
    def stop(self) -> bool: ...
    @abc.abstractmethod
    def collect(self) -> List[Dict[str, Any]]: ...
    def health(self) -> Dict[str, Any]: ...
```

### Fault Isolation:
The `CollectorRegistry` encapsulates collector polling with isolated try/catch boundaries. If a hardware hook or platform collector raises an unhandled error:
* The failing collector's error count is incremented and status marked `DEGRADED`.
* Other registered collectors continue collecting telemetry without interruption.
* The overall agent remains online and reports the failure in the next periodic heartbeat.

---

## 10. Raw Telemetry Event Model & Provenance

Raw telemetry is preserved in `EndpointTelemetryEventModel` before pipeline normalization:

```
event_id                : UUID v4 (Client generated)
agent_id                : FK -> endpoint_agents.id
device_id               : FK -> devices.id
workspace_id            : Derived tenant ID
sequence_number         : Monotonic integer per agent stream
event_type              : PROCESS | NETWORK | DNS | AUTHENTICATION | SYSTEM | FILE_METADATA
event_time              : Local endpoint event timestamp
received_at             : Server ingestion timestamp
collector_id            : Adapter identifier
schema_version          : "1.0.0"
priority                : CRITICAL | HIGH | NORMAL | LOW
payload_json            : Redacted JSON dictionary
threat_event_id         : FK -> threat_events.id (Normalized record)
```

---

## 11. Monotonic Sequence Numbers & Deduplication

Network retransmissions are expected in distributed endpoint environments. To prevent duplicate security event inflation:

1. **Client Monotonic Counters**: The agent increments an atomic integer `sequence_number` for each event emitted during a session.
2. **Composite Deduplication Index**: The backend enforces a unique database index across:
   $$(\text{agent\_id}, \text{sequence\_number}, \text{event\_id})$$
3. **Idempotent Acknowledgment**: When an agent retransmits previously accepted events, the server detects the duplicate, increments `duplicate_count`, and returns an idempotent `ACK` containing the `event_id`, enabling the agent to safely clear its local buffer without creating duplicate `ThreatEventModel` records.

---

## 12. Clock Skew Tracking

Endpoint clocks frequently drift or suffer misconfiguration. Rather than silently mutating original event timestamps:
* The server computes clock offset upon batch receipt:
  $$\text{clock\_offset\_ms} = (T_{\text{server\_received}} - T_{\text{batch\_timestamp}}) \times 1000$$
* Both `event_time` and `received_at` are permanently stored.
* The computed offset is recorded in `EndpointAgentModel.clock_offset_ms` and attached to `ThreatEventModel.metadata_json` for temporal correlation analysis (Section 16).

---

## 13. Bounded Local Event Buffer

To survive temporary network outages and backend maintenance windows without unbounded memory growth, the agent utilizes `LocalEventBuffer`:

* **Capacity Constraints**: Configurable `max_events` (default: 5,000) and `max_bytes` (default: 20 MB).
* **Priority Queueing**: Events are ordered by `CRITICAL` > `HIGH` > `NORMAL` > `LOW`.
* **Overflow Policies**:
  * `DROP_LOW_PRIORITY`: Drops `LOW` then `NORMAL` events to preserve space for `HIGH` and `CRITICAL` telemetry.
  * `DROP_OLDEST`: Drops oldest non-critical events.
  * `BLOCK_COLLECTOR`: Rejects new collections until the buffer drains.
* **Auditability**: Dropped events are permanently tallied and reported in heartbeat metrics.

---

## 14. Client-Side Privacy & Data Minimization

The `PrivacyFilter` executes on the client **before** events are stored in the local buffer or transmitted over the wire:

* **Key-Level Redaction**: Recursively replaces values for sensitive keys (`password`, `token`, `secret`, `api_key`, `authorization`, `cookie`, `private_key`) with `"[REDACTED]"`.
* **Pattern-Level Redaction**: Replaces regex matches for Bearer tokens, Basic auth credentials, private key blocks, and AWS keys within string command lines or logs.
* **Exclusion Filtering**:
  * `excluded_paths`: e.g. `*/Documents/Personal/*`, `*/.ssh/id_*`, `*/Library/Keychains/*`.
  * `excluded_processes`: e.g. password managers (`1Password*`, `Bitwarden*`).
  * `excluded_users`: Specific service accounts or privacy-protected users.
* **Data Minimization**: For file access events, only file path, hash, and metadata are captured—full document contents are never ingested.

---

## 15. Transport Client & Resilient Dispatch

The `AgentTransportClient` handles HTTPS communication with full retry resilience:
* **TLS Validation**: Enforced by default (`verify_ssl=True` with system or custom CA bundle).
* **Exponential Backoff with Full Jitter**:
  $$\text{Sleep} = \min(\text{max\_backoff}, \text{initial\_backoff} \times 2^{\text{attempt}-1}) \times \text{random}(0.5, 1.5)$$
* **Backpressure Management**: HTTP 429 and 503 responses cause the transport to back off without dropping buffered events.
* **Partial Batch Handling**: If some events in a batch fail schema validation while others succeed, the server returns granular `accepted_event_ids` and `rejected_event_ids`. The client removes accepted events from the buffer and retries only transiently failed items.

---

## 16. Agent Heartbeat & Health Monitoring

The agent periodically transmits an `AgentHeartbeatRequest` to `/api/v1/endpoint/heartbeat`:

| Metric | Source | Purpose |
| :--- | :--- | :--- |
| `health_state` | `AgentHealthReporter` | `HEALTHY`, `DEGRADED`, `BUFFER_PRESSURE`, `COLLECTOR_FAILURE` |
| `collector_states` | `CollectorRegistry` | Health and restart counts for each collector adapter |
| `buffer_events_count` | `LocalEventBuffer` | Queue depth and backpressure indicator |
| `cpu_usage_percent` | Host profiler | CPU resource consumption safety check |
| `memory_usage_mb` | Process RSS | Memory footprint compliance check |

If the server configuration version has advanced, the heartbeat response returns `reconfigure_required=True`, prompting the agent to fetch the updated signed configuration.

---

## 17. ThreatEvent Pipeline Integration

Accepted raw events are transformed into canonical `ThreatEventModel` records:
* `event_type`: `endpoint_process`, `endpoint_dns`, `endpoint_network`, `endpoint_authentication`, `endpoint_file_metadata`.
* `severity`: `HIGH` for critical/high priority telemetry; `LOW` for routine telemetry.
* `status`: `OPEN`.
* `summary`: Descriptive human-readable summary detailing host, platform, and collector.
* `metadata`: Complete redacted payload, sequence number, and provenance IDs.

---

## 18. Security Knowledge Graph Integration

Every enrolled agent and ingested telemetry event establishes relationships in the central polymorphic graph (`RelationshipModel`):

1. **Enrollment Relationship**:
   $$\text{Agent (AGT-XXXX)} \xrightarrow{\text{COLLECTS\_FROM}} \text{Device (DEV-XXXX)}$$
2. **Telemetry Ingestion Relationship**:
   $$\text{Device (DEV-XXXX)} \xrightarrow{\text{HAS\_EVENT}} \text{ThreatEvent (UUID)}$$
3. **Subsequent Investigations**:
   Enables automated multi-hop traversal from an incident artifact or threat indicator to the affected endpoint device and all associated endpoint observations.

---

## 19. Threat Memory & Behavioral Baseline Boundaries

* **Threat Memory Boundary**: Raw endpoint events are **never** written directly to Threat Memory (Section 23). Threat Memory is reserved for high-fidelity, verified attack patterns and recurring campaign infrastructure.
* **Behavioral Baseline Boundary**: Ingested endpoint events feed temporal and user activity metrics for Section 21 Behavioral Baselines (e.g. host login hours, normal parent-child process pairs, corporate network destinations) without performing complex machine learning on the client.

---

## 20. Administrative Fleet Management & Revocation

Administrators manage enrolled agents via dedicated endpoints:
* `GET /api/v1/endpoint/agents`: Lists all agents with status, version, and last seen timestamps.
* `GET /api/v1/endpoint/devices`: Displays registered hardware inventory.
* `POST /api/v1/endpoint/agents/{agent_id}/revoke`: Immediately marks agent status as `REVOKED` and invalidates all associated machine credentials. Subsequent requests from the revoked agent are rejected with `401 Unauthorized`.
* `GET /api/v1/endpoint/metrics`: Returns fleet-wide counters for operational observability.

---

## 21. Synthetic Test Harness

To enable safe end-to-end testing without hooking live OS kernels, Section 31 includes `SyntheticCollector` and test endpoints:
* Generates safe, simulated process, DNS, network, and authentication events.
* Emits strictly benign payloads with `synthetic: true` metadata.
* Fully exercises the normalizer, local buffer, transport client, ingestion gateway, deduplication engine, and knowledge graph.

---

## 22. Boundary to Section 32 (Endpoint Telemetry)

* **Section 31 (This Section)**: Establishes agent architecture, contracts, enrollment, mutual machine authentication, credential rotation, versioned configuration, buffering, transport, deduplication, schema validation, and pipeline integration.
* **Section 32 (Future Section)**: Will implement the concrete host telemetry collectors (macOS Endpoint Security Framework / Windows ETW / Linux eBPF collectors).
* **Verification**: Concrete kernel drivers and low-level OS telemetry interceptors were **NOT** implemented in Section 31, preserving clean architectural boundaries.
