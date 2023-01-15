.PHONY: lint

lint:
	@luacheck -q ./lib

test:
	busted
