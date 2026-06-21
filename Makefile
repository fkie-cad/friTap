# friTap maintainer tasks (public/private tiering).
#
# The full tree lives on the `gitlab` remote (source of truth). The public
# GitHub/PyPI build is a regenerated snapshot = the full tree minus private.txt
# paths, with the substantive Signal-E2E reveals scrubbed. See TIERING_HANDOFF.md.
.PHONY: publish-public publish-public-dry leak-guard verify-public help

help:
	@echo "friTap maintainer targets:"
	@echo "  make verify-public       — preview the public strip + token scan (scripts/verify_public_build.sh)"
	@echo "  make leak-guard          — §F leak guard on the stripped public tree (scripts/check_public_denylist.sh)"
	@echo "  make publish-public-dry  — §E dry-run: strip + scrub + leak guard, NO git writes"
	@echo "  make publish-public      — §E: the above, then commit-tree onto local public-main (maintainer)"
	@echo "                             vars: MSG=\"<commit message>\"  NORELEASE=1 (freeze about.py → no PyPI)"

# §E — regenerate the scrubbed public snapshot onto local public-main.
#   make publish-public MSG="my first public commit"   # custom snapshot message
#   make publish-public NORELEASE=1                     # code mirror only, no PyPI release
publish-public:
	bash scripts/publish_public.sh $(if $(MSG),-m "$(MSG)") $(if $(NORELEASE),--no-release)

# §E dry-run — strip + scrub + leak guard only (no git objects/refs written).
publish-public-dry:
	bash scripts/publish_public.sh --dry-run

# §F — name-free leak guard (structural rules + denylist token scan).
leak-guard:
	bash scripts/check_public_denylist.sh

# Dev harness — preview the publishable strip and token residuals.
verify-public:
	bash scripts/verify_public_build.sh
