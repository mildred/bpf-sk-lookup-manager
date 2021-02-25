default: src/sk_lookup_manager
.PHONY: default

src/sk_lookup_manager:
	$(MAKE) -C src sk_lookup_manager

.PHONY: src/sk_lookup_manager
