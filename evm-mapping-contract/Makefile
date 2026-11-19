ROOT_DIR 		:= $(abspath .)
BIN_DIR			:= bin

TARGET = contract/main.go
WASM = $(BIN_DIR)/main.wasm
BUILD_FLAGS = -gc=custom -scheduler=none -panic=trap -no-debug -target=wasm-unknown

TINYJSON		:= tinyjson
TINYJSON_FLAGS 	:= -snake_case -no_std_marshalers
CONTRACTS_DIR	:= contract

# MED-73 (F1) supply-chain fix: pin the TinyGo build image by immutable content
# digest, NOT by the mutable `tinygo/tinygo:0.39.0` tag. A Docker Hub tag can be
# re-pushed by whoever controls the upstream repo (or via a registry
# compromise), silently swapping the compiler and producing a different
# (potentially backdoored) contract WASM whose CID no longer matches what was
# reviewed. Docker enforces the digest after the `@`; the tag is kept for
# readability only. On any TinyGo upgrade, bump BOTH the tag and the digest
# together (resolve with: docker buildx imagetools inspect tinygo/tinygo:<tag>).
TINYGO_IMAGE := tinygo/tinygo:0.39.0@sha256:0e51d243c1b84ec650f2dcd1cce3a09bb09730e1134771aeace2240ade4b32f5
WORKDIR      := /work

# For each local path in go.work (use/replace directives), add a Docker volume
# mount so the container can resolve the same relative paths as the host.
# Container path is computed by normalising WORKDIR/relative_path.
GOWORK_EXTRA_MOUNTS := $(if $(wildcard go.work),$(shell \
  awk '($$1=="use"||$$1=="replace") && $$NF~/^(\.|\/|~)/ && $$NF!="." {print $$NF}' go.work 2>/dev/null | \
  while read rel; do \
    host=$$(realpath "$(CURDIR)/$$rel" 2>/dev/null); \
    ctr=$$(python3 -c "import os,sys; print(os.path.normpath(sys.argv[1]))" "$(WORKDIR)/$$rel"); \
    [ -d "$$host" ] && printf -- '-v %s:%s ' "$$host" "$$ctr"; \
  done),)

# As the calling user (the files it writes stay theirs), so Go's module and
# build caches go to /tmp: the image's /go is not writable for that user.
TINYGO_CMD = docker run --rm \
    -u $(shell id -u):$(shell id -g) \
    -e HOME=/tmp -e GOPATH=/tmp/go -e GOCACHE=/tmp/gocache \
    $(GOWORK_EXTRA_MOUNTS) \
    -v $(CURDIR):$(WORKDIR) \
    -w $(WORKDIR) \
    $(TINYGO_IMAGE) \
    tinygo

ifeq ($(USE_DOCKER),0)
    TINYGO_CMD = tinygo
endif

FILTER ?= .

RUN_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
ifneq ($(RUN_ARGS),)
  ifeq ($(firstword $(MAKECMDGOALS)),test)
    FILTER := $(firstword $(RUN_ARGS))
  endif
endif
$(eval $(RUN_ARGS):;@:)

all: build

pull-tinygo:
	docker pull $(TINYGO_IMAGE)

MODULE := $(shell head -1 go.mod | awk '{print $$2}')

build:
	@mkdir -p $(BIN_DIR); \
	wasm_file="$(WASM)"; \
	dir="$(ROOT_DIR)/$(dir $(TARGET))"; \
	dir="$${dir%/}"; \
	if [ -f "$$wasm_file" ]; then \
		dep_dirs="$$dir"; \
		queue="$$dir"; \
		while [ -n "$$queue" ]; do \
			next_queue=""; \
			for d in $$queue; do \
				for imp in $$(grep -roh '"$(MODULE)/[^"]*"' "$$d"/*.go 2>/dev/null | tr -d '"' | sed 's|$(MODULE)/||' | sort -u); do \
					resolved="$(ROOT_DIR)/$$imp"; \
					case " $$dep_dirs " in \
						*" $$resolved "*) ;; \
						*) [ -d "$$resolved" ] && dep_dirs="$$dep_dirs $$resolved" && next_queue="$$next_queue $$resolved" ;; \
					esac; \
				done; \
			done; \
			queue="$$next_queue"; \
		done; \
		needs_rebuild=0; \
		for dep_dir in $$dep_dirs; do \
			if find "$$dep_dir" -maxdepth 1 -type f -name '*.go' -newer "$$wasm_file" 2>/dev/null | grep -q .; then \
				needs_rebuild=1; \
				break; \
			fi; \
		done; \
		if [ "$$needs_rebuild" -eq 0 ] && \
		   [ ! "$(ROOT_DIR)/go.mod" -nt "$$wasm_file" ] && \
		   [ ! "$(ROOT_DIR)/go.sum" -nt "$$wasm_file" ]; then \
			echo "⏩ $$wasm_file is up to date, skipping"; \
		else \
			echo "Building $$wasm_file ..."; \
			$(TINYGO_CMD) build $(BUILD_FLAGS) -o $$wasm_file $(TARGET); \
		fi; \
	else \
		echo "Building $$wasm_file ..."; \
		$(TINYGO_CMD) build $(BUILD_FLAGS) -o $$wasm_file $(TARGET); \
	fi

strip:
	@for file in $(BIN_DIR)/*.wasm; do \
		case "$$file" in \
			*"-stripped.wasm") \
				continue ;; \
			*) \
				base=$${file%.wasm}; \
				wasm-tools strip -o "$${base}-stripped.wasm" "$$file"; \
				echo "Stripped $$file -> $${base}-stripped.wasm" ;; \
		esac; \
	done

tinyjson:
	@set +e; \
	echo "Searching for //tinyjson:json directives..."; \
	\
	# Ensure tinyjson exists \
	if ! command -v $(TINYJSON) >/dev/null 2>&1; then \
		echo "tinyjson not found, installing..."; \
		go install github.com/CosmWasm/tinyjson/tinyjson@v0.9.0 || \
			{ echo "Failed to install tinyjson"; exit 1; }; \
	fi; \
	\
	# Find all directories containing files with tinyjson tags \
	find $(ROOT_DIR) -type f -name '*.go' -print0 | \
	xargs -0 grep -l '^//tinyjson:json$$' | \
	xargs -n1 dirname | \
	sort -u | \
	awk '{ if ($$0 ~ /\/sdk$$/) print "0" $$0; else print "1" $$0 }' | \
	sort | \
	sed 's/^.//' | \
	while read dir; do \
		echo "Processing package in $$dir"; \
		\
		# Ensure cleanup happens on exit \
		trap 'rm -rf "$$dir/.tinyjson-tmp" 2>/dev/null' EXIT INT TERM; \
		\
		# Find the output file (assume it's *_tinyjson.go) \
		out=$$(find "$$dir" -maxdepth 1 -name '*_tinyjson.go' -print -quit); \
		\
		rebuild=0; \
		\
		# Rebuild if output missing \
		if [ -z "$$out" ] || [ ! -f "$$out" ]; then \
			echo "  Output file missing or not found"; \
			rebuild=1; \
		\
		# Rebuild if any source file with tinyjson tag is newer than output (excluding _tinyjson.go files) \
		elif find "$$dir" -maxdepth 1 -name '*.go' ! -name '*_tinyjson.go' -type f -newer "$$out" -exec grep -l '^//tinyjson:json$$' {} + | grep -q . ; then \
			echo "  Source files newer than output"; \
			rebuild=1; \
		\
		# Rebuild if output contains stub marshalers \
		elif [ -f "$$out" ] && \
			! awk '/func[[:space:]]+\([^)]+\)[[:space:]]+MarshalTinyJSON\(/ { inside=1; next } \
			inside && /\{\}[[:space:]]*$$/ { exit 1 } inside && /\{/ { inside=0 }' "$$out" && \
			! awk '/func[[:space:]]+\([^)]+\)[[:space:]]+UnmarshalTinyJSON\(/ { inside=1; next } \
			inside && /\{\}[[:space:]]*$$/ { exit 1 } inside && /\{/ { inside=0 }' "$$out"; then \
			echo "  ⚠️  stub-only function detected"; \
			rebuild=1; \
		fi; \
		\
		if [ "$$rebuild" -eq 0 ]; then \
			echo "  ⏩ $$out is up to date, skipping"; \
			continue; \
		fi; \
		\
		# Find a source file with tinyjson tag to use as template \
		src=$$(find "$$dir" -maxdepth 1 -name '*.go' -type f -exec grep -l '^//tinyjson:json$$' {} \; | head -n 1); \
		\
		if [ -z "$$src" ]; then \
			echo "  ⚠️  No source file with tinyjson tag found in $$dir"; \
			continue; \
		fi; \
		\
		# Get the original package name \
		original_pkg=$$(awk '/^package / {print $$2; exit}' "$$src"); \
		\
		if [ -z "$$original_pkg" ]; then \
			echo "  ⚠️  Could not determine package name in $$src"; \
			continue; \
		fi; \
		\
		if (mkdir -p "$$dir/.tinyjson-tmp" && \
			find "$$dir" -maxdepth 1 -name '*.go' ! -name '*_tinyjson.go' ! -name '*_test.go' -exec cp {} "$$dir/.tinyjson-tmp/" \; && \
			cd "$$dir/.tinyjson-tmp" && \
			for f in *.go; do \
				awk '/^package / {sub(/package .*/, "package tinyjson")} {print}' "$$f" > "$$f.tmp" && mv "$$f.tmp" "$$f"; \
			done && \
			$(TINYJSON) $(TINYJSON_FLAGS) -pkg -output_filename "$${original_pkg}_tinyjson.go" && \
			for f in *_tinyjson.go; do \
				[ -f "$$f" ] && sed "s/package tinyjson/package $$original_pkg/" "$$f" > "../$$f"; \
			done && \
			cd .. && \
			rm -rf .tinyjson-tmp); then \
			echo "  ✅  tinyjson created for $$dir" ; \
		else \
			echo "  ⚠️  tinyjson failed for $$dir (continuing)"; \
			rm -rf "$$dir/.tinyjson-tmp" 2>/dev/null; \
		fi; \
	done

test:
	go test -v -run "$(FILTER)" ./...

clean:
	rm -rf $(BIN_DIR)/*.wasm

.PHONY: all build pull-tinygo strip tinyjson test clean
