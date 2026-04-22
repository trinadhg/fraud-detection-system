# Fraud Detection System

Agentic fraud detection system using Google ADK, MCP, and Neo4j graph database.

## Architecture

- **Google ADK** — Agent orchestration (SequentialAgent, ParallelAgent, LlmAgent)
- **MCP Server** — Tool layer exposing Neo4j, Redis, watchlists to agents
- **Neo4j** — Graph database for multi-hop fraud inference
- **Redpanda** — Kafka-compatible event streaming
- **Redis** — Session memory and caching
- **ChromaDB** — Vector store for cross-session agent memory
- **Jaeger** — Distributed tracing and observability

## Fraud Domains

- Credit card fraud
- AML / wire transfer / money laundering
- Synthetic identity fraud
- Account takeover

## Quick Start

### Prerequisites
- Docker Desktop with WSL2
- Python 3.11
- gcloud CLI authenticated

### Run
```bash
cp .env.example .env
# Edit .env with your values
make up
make urls
```

## Services

| Service | URL |
|---|---|
| Neo4j Browser | http://localhost:7474 |
| Redpanda Console | http://localhost:8080 |
| Jaeger UI | http://localhost:16686 |
| MCP Server | http://localhost:8001 |
| Orchestrator API | http://localhost:8002 |

## Dataset

Uses PaySim synthetic financial dataset.

<img width="842" height="720" alt="image" src="https://github.com/user-attachments/assets/7cc9ff67-2fd8-431f-aa67-5d5c0424fab6" />
