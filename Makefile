.PHONY: lint test docs

lint:
	@luacheck -q ./lib

test:
	busted

docs:
	ldoc .
