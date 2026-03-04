TESTBED_COMPOSE=testbed/docker/docker-compose.yml

testbed-up:
	docker compose -f $(TESTBED_COMPOSE) up -d bootstrap node2 relay

testbed-check:
	docker compose -f $(TESTBED_COMPOSE) run --rm checker

testbed-down:
	docker compose -f $(TESTBED_COMPOSE) down -v

testbed: testbed-up testbed-check
