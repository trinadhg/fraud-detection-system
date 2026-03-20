.PHONY: up down restart logs ps clean build help

# ─── Core Commands ────────────────────────────────────────────

up:
	docker compose up -d

down:
	docker compose down

restart:
	docker compose down && docker compose up -d

build:
	docker compose build --no-cache

# ─── Monitoring ───────────────────────────────────────────────

logs:
	docker compose logs -f

logs-neo4j:
	docker compose logs -f neo4j

logs-mcp:
	docker compose logs -f mcp-server

logs-orchestrator:
	docker compose logs -f orchestrator

ps:
	docker compose ps

# ─── Database ─────────────────────────────────────────────────

neo4j-shell:
	docker exec -it fraud-neo4j cypher-shell -u ${NEO4J_USER} -p ${NEO4J_PASSWORD}

load-schema:
	docker exec -it fraud-neo4j cypher-shell -u ${NEO4J_USER} -p ${NEO4J_PASSWORD} -f /var/lib/neo4j/import/schema/schema.cypher

load-seed-data:
	docker exec -it fraud-neo4j cypher-shell -u ${NEO4J_USER} -p ${NEO4J_PASSWORD} -f /var/lib/neo4j/import/seed-data/paysim.cypher

# ─── Redis ────────────────────────────────────────────────────

redis-cli:
	docker exec -it fraud-redis redis-cli -a ${REDIS_PASSWORD}

# ─── Testing ──────────────────────────────────────────────────

test-unit:
	C:\Python311\python.exe -m pytest tests/unit -v

test-integration:
	C:\Python311\python.exe -m pytest tests/integration -v

test-e2e:
	C:\Python311\python.exe -m pytest tests/e2e -v

test:
	C:\Python311\python.exe -m pytest tests/ -v

# ─── Cleanup ──────────────────────────────────────────────────

clean:
	docker compose down -v --remove-orphans
	docker system prune -f

clean-data:
	docker volume rm fraud-detection_neo4j-data fraud-detection_redis-data fraud-detection_chroma-data fraud-detection_redpanda-data

# ─── URLs ─────────────────────────────────────────────────────

urls:
	@echo Neo4j Browser:       http://localhost:7474
	@echo Redpanda Console:    http://localhost:8080
	@echo Jaeger UI:           http://localhost:16686
	@echo MCP Server:          http://localhost:8001
	@echo Orchestrator API:    http://localhost:8002
	@echo ChromaDB:            http://localhost:8000

# ─── Help ─────────────────────────────────────────────────────

help:
	@echo Available commands:
	@echo   make up              - Start all services
	@echo   make down            - Stop all services
	@echo   make restart         - Restart all services
	@echo   make build           - Rebuild all images
	@echo   make logs            - Tail all logs
	@echo   make ps              - Show running containers
	@echo   make neo4j-shell     - Open Neo4j Cypher shell
	@echo   make load-schema     - Load graph schema
	@echo   make load-seed-data  - Load PaySim dataset
	@echo   make redis-cli       - Open Redis CLI
	@echo   make test            - Run all tests
	@echo   make clean           - Stop and remove all volumes
	@echo   make urls            - Show all service URLs