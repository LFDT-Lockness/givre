.PHONY: docs docs-open

docs:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --all-features

docs-open:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --all-features --open

docs-private:
	RUSTDOCFLAGS="--html-in-header katex-header.html --cfg docsrs" cargo +nightly doc --no-deps --all-features --document-private-items

readme:
	cargo readme --no-title -r givre -i src/lib.rs \
		| perl -ne 's/(?<!!)\[([^\[]+?)\]\([^\(]+?\)/\1/g; print;' \
		| perl -ne 's/\[mod@([^\[]+?)\]/\1/g; print;' \
		> README.md

