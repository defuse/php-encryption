TARGETS := defuse-crypto.phar

define install_tool
	@echo 'Required tool \"$1\" not installed, see docs/InstallingAndVerifying.md'; false
endef
define which
	$(shell PATH=$$PATH:. which $1.phar 2>/dev/null || which $1 2>/dev/null || { echo "$(call install_tool,$(1))"; })
endef
define find_tool
	$(call which,$1)
endef

box := $(call find_tool,box)
composer := $(call find_tool,composer)
php := $(call find_tool,php)

phar: $(TARGETS)

composer.lock:
	$(composer) install --no-dev

%.phar: Makefile box.json composer.lock
	$(php) -d phar.readonly=0 $(box) build -v

clean:
	rm -vf $(TARGETS)
