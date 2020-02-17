.PHONY: local
MAKEFLAGS += --silent

local:
	docker-compose up -d
	node init-keycloak.js
