.PHONY: docs docs-open

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --all-features

docs-open:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --all-features --open

docs-private:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --all-features --document-private-items

readme:
	cargo readme --no-title -r givre -i src/lib.rs \
		| sed -E 's/(\/\*.+\*\/)/\1;/' \
		| sed -E '/^\[`.+`\]:/d' \
		| sed -E 's/\[`([^`]*)`\]\(.+?\)/`\1`/g' \
		| sed -E 's/\[`([^`]*)`\]/`\1`/g' \
		| sed -E 's/\[mod@([^\[]*)\]/`\1`/g' \
		| perl -ne 's/(?<!!)\[([^\[]+?)\]\([^\(]+?\)/\1/g; print;' \
		| sed -E '/^#$$/d' \
		> README.md

