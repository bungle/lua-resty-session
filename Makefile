.PHONY: lint

lint:
	@luacheck -q ./lib

test:
	luacheck .
	busted
