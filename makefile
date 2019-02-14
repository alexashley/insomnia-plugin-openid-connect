.PHONY: local
MAKEFLAGS += --silent

local:
	sudo docker-compose up -d
	node init-keycloak.js
