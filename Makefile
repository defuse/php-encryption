TARGETS := defuse-crypto.phar

define find_tool
$(shell PATH=$$PATH:. which $1.phar 2>/dev/null || which $1 2>/dev/null || $(error Required tool `$1' not installed, see docs/InstallingAndVerifying.md))
endef

box := $(call find_tool,box)
composer := $(call find_tool,composer)
php := $(call find_tool,php)

phar: $(TARGETS)

composer.lock:
	$(composer) install --no-dev

%.phar: Makefile box.json composer.lock
	$(php) -d phar.readonly=0 $(box) build -v

box.phar:
	@echo Required tool $@ not installed, see docs/InstallingAndVerifying.md

composer.phar:
	@echo Required tool $@ not installed, see docs/InstallingAndVerifying.md

clean:
	rm -vf $(TARGETS)
