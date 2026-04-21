"""
scripts/init_schema.py

Initializes Neo4j schema on startup.
Runs all Cypher files in order: 00 → 01 → 02 → 03 → 04
Idempotent — safe to run multiple times (IF NOT EXISTS on all constraints/indexes)

Usage:
    python scripts/init_schema.py

Environment variables (from .env):
    NEO4J_URI       — bolt://localhost:7687
    NEO4J_USER      — neo4j
    NEO4J_PASSWORD  — FraudDetect@2024
"""

import os
import sys
import logging
from pathlib import Path
from neo4j import GraphDatabase
from neo4j.exceptions import Neo4jError
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
NEO4J_URI      = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")

SCHEMA_DIR = Path(__file__).parent.parent / "graph" / "schema"

SCHEMA_FILES = [
    "00_constraints_indexes.cypher",
    # 01-04 are ingestion templates — executed by the ingestion service, not here
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_statements(cypher_text: str) -> list[str]:
    """
    Split a Cypher file into individual statements on semicolons.
    Strips comments (lines starting with //) and blank lines.
    Returns only non-empty statements.
    """
    lines = []
    for line in cypher_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped == "":
            continue
        lines.append(line)

    raw = "\n".join(lines)
    statements = [s.strip() for s in raw.split(";")]
    return [s for s in statements if s]


def run_file(session, filepath: Path) -> tuple[int, int]:
    """
    Run a single Cypher file against Neo4j.
    Returns (success_count, error_count).
    """
    log.info(f"Running {filepath.name}")
    cypher_text = filepath.read_text(encoding="utf-8")
    statements = parse_statements(cypher_text)

    success = 0
    errors  = 0

    for i, stmt in enumerate(statements, 1):
        try:
            session.run(stmt)
            success += 1
        except Neo4jError as e:
            # Fail fast on unexpected errors
            # Expected: IF NOT EXISTS makes most statements idempotent
            # Unexpected: syntax errors, version incompatibilities
            log.error(f"  Statement {i} FAILED: {e.code}")
            log.error(f"  Statement: {stmt[:120]}...")
            errors += 1

    log.info(f"  {filepath.name}: {success} ok, {errors} errors")
    return success, errors


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    if not NEO4J_PASSWORD:
        log.error("NEO4J_PASSWORD not set in environment")
        sys.exit(1)

    if not SCHEMA_DIR.exists():
        log.error(f"Schema directory not found: {SCHEMA_DIR}")
        log.error("Expected: graph/schema/ at repo root")
        sys.exit(1)

    # Verify all files exist before connecting
    missing = [f for f in SCHEMA_FILES if not (SCHEMA_DIR / f).exists()]
    if missing:
        log.error(f"Missing schema files: {missing}")
        sys.exit(1)

    log.info(f"Connecting to Neo4j at {NEO4J_URI}")
    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(NEO4J_USER, NEO4J_PASSWORD),
        connection_timeout=30,
        max_connection_lifetime=300,
    )

    try:
        driver.verify_connectivity()
        log.info("Neo4j connection verified")
    except Exception as e:
        log.error(f"Cannot connect to Neo4j: {e}")
        log.error("Is Neo4j running? Check: docker ps | grep neo4j")
        sys.exit(1)

    total_success = 0
    total_errors  = 0

    with driver.session(database="neo4j") as session:
        for filename in SCHEMA_FILES:
            filepath = SCHEMA_DIR / filename
            s, e = run_file(session, filepath)
            total_success += s
            total_errors  += e

            # Fail fast — stop on first file with errors
            if e > 0:
                log.error(f"Stopping due to errors in {filename}")
                log.error("Fix errors before proceeding — schema may be partial")
                driver.close()
                sys.exit(1)

    driver.close()

    log.info("=" * 60)
    log.info(f"Schema init complete: {total_success} statements ok")
    log.info("Neo4j is ready")


if __name__ == "__main__":
    main()