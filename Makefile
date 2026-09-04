VERSION = $(shell git describe --tags --always --dirty)
INTERACTIVE ?= i
# Container runtime for the *_uring targets; podman accepts the same flags
DOCKER ?= docker
# The *_uring targets serve the filesystem over FUSE-over-io_uring under
# tests/seccomp-io-uring.json, Docker's default profile plus the io_uring syscalls (see
# tests/seccomp-io-uring.md). The host kernel must have fuse.enable_uring=Y: the module
# parameter is not namespaced
URING_BUILD_ARG = --build-arg BUILD_FEATURES='--features=io-uring'
URING_RUN_OPTS = --security-opt "seccomp=$(shell pwd)/tests/seccomp-io-uring.json" -e FUSER_URING_FLAGS=--io-uring


build: pre
	cargo build --examples --features=experimental

format:
	cargo fmt --all

pre:
	cargo fmt --all -- --check
	cargo deny check licenses
	cargo clippy --all-targets
	cargo clippy --all-targets --no-default-features
	cargo clippy --all-targets --all-features

xfstests:
	docker build -t fuser:xfstests -f xfstests.Dockerfile .
	# Additional permissions are needed to be able to mount FUSE
	# LINUX_IMMUTABLE is for chattr +i/+a, and SYS_PACCT for BSD process accounting. Neither
	# is in Docker's default set, and without them those tests fail rather than skip.
	# The seccomp profile is left on: turning it off would let the io_uring tests run, but it
	# also unblocks swapon, and swap is a global resource rather than a per-container one
	docker run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --cap-add IPC_OWNER --cap-add SYS_PACCT \
	 --cap-add LINUX_IMMUTABLE --device /dev/fuse --security-opt apparmor:unconfined \
	 --memory=2g --kernel-memory=200m \
	 -v "$(shell pwd)/logs:/code/logs" fuser:xfstests bash -c "cd /code/fuser && ./xfstests.sh"

xfstests_uring:
	$(DOCKER) build $(URING_BUILD_ARG) -t fuser:xfstests-uring -f xfstests.Dockerfile .
	$(DOCKER) run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --cap-add IPC_OWNER --cap-add SYS_PACCT \
	 --cap-add LINUX_IMMUTABLE --device /dev/fuse --security-opt apparmor=unconfined $(URING_RUN_OPTS) \
	 --memory=2g \
	 -v "$(shell pwd)/logs:/code/logs" fuser:xfstests-uring bash -c "cd /code/fuser && ./xfstests.sh"

pjdfs_tests: pjdfs_tests_fuse2 pjdfs_tests_fuse3 pjdfs_tests_pure

pjdfs_tests_fuse2:
	docker build --build-arg BUILD_FEATURES='--features=libfuse2' -t fuser:pjdfs-2 -f pjdfs.Dockerfile .
	# Additional permissions are needed to be able to mount FUSE
	docker run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
	 -v "$(shell pwd)/logs:/code/logs" fuser:pjdfs-2 bash -c "cd /code/fuser && ./pjdfs.sh"

pjdfs_tests_fuse3:
	docker build --build-arg BUILD_FEATURES='--features=libfuse3' -t fuser:pjdfs-3 -f pjdfs.Dockerfile .
	# Additional permissions are needed to be able to mount FUSE
	docker run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
	 -v "$(shell pwd)/logs:/code/logs" fuser:pjdfs-3 bash -c "cd /code/fuser && ./pjdfs.sh"

pjdfs_tests_pure:
	docker build --build-arg BUILD_FEATURES='' -t fuser:pjdfs-pure -f pjdfs.Dockerfile .
	# Additional permissions are needed to be able to mount FUSE
	docker run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
	 -v "$(shell pwd)/logs:/code/logs" fuser:pjdfs-pure bash -c "cd /code/fuser && ./pjdfs.sh"

pjdfs_tests_uring:
	$(DOCKER) build $(URING_BUILD_ARG) -t fuser:pjdfs-uring -f pjdfs.Dockerfile .
	$(DOCKER) run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor=unconfined $(URING_RUN_OPTS) \
	 -v "$(shell pwd)/logs:/code/logs" fuser:pjdfs-uring bash -c "cd /code/fuser && ./pjdfs.sh"

mount_tests:
	docker build -t fuser:mount_tests_libfuse2 -f mount_tests_libfuse2.Dockerfile .
	docker build -t fuser:mount_tests_libfuse3 -f mount_tests_libfuse3.Dockerfile .
	mkdir -p docker-cargo-caches/target docker-cargo-caches/git docker-cargo-caches/registry
	# Additional permissions are needed to be able to mount FUSE
	docker run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
	 -v "$(shell pwd)/docker-cargo-caches/target:/code/fuser/target" \
	 -v "$(shell pwd)/docker-cargo-caches/git:/root/.cargo/git" \
	 -v "$(shell pwd)/docker-cargo-caches/registry:/root/.cargo/registry" \
	 fuser:mount_tests_libfuse3 bash -c "cd /code/fuser && cargo run -p fuser-tests -- simple"
	docker run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
	 -v "$(shell pwd)/docker-cargo-caches/target:/code/fuser/target" \
	 -v "$(shell pwd)/docker-cargo-caches/git:/root/.cargo/git" \
	 -v "$(shell pwd)/docker-cargo-caches/registry:/root/.cargo/registry" \
	 fuser:mount_tests_libfuse2 bash -c "cd /code/fuser && cargo run -p fuser-tests -- linux-mount-libfuse2"
	docker run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
	 -v "$(shell pwd)/docker-cargo-caches/target:/code/fuser/target" \
	 -v "$(shell pwd)/docker-cargo-caches/git:/root/.cargo/git" \
	 -v "$(shell pwd)/docker-cargo-caches/registry:/root/.cargo/registry" \
	 fuser:mount_tests_libfuse3 bash -c "cd /code/fuser && cargo run -p fuser-tests -- linux-mount-libfuse3"
# Under Docker's default seccomp profile this takes the /dev/fuse fallback; the *_uring
# targets are where the rings are exercised
	docker run --rm -$(INTERACTIVE)t --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor:unconfined \
	 -v "$(shell pwd)/docker-cargo-caches/target:/code/fuser/target" \
	 -v "$(shell pwd)/docker-cargo-caches/git:/root/.cargo/git" \
	 -v "$(shell pwd)/docker-cargo-caches/registry:/root/.cargo/registry" \
	 fuser:mount_tests_libfuse3 bash -c "cd /code/fuser && cargo run -p fuser-tests -- linux-io-uring"

test_passthrough:
	cargo build --example passthrough --example passthrough_fork
	sudo tests/test_passthrough.sh target/debug/examples/passthrough
	sudo tests/test_passthrough.sh target/debug/examples/passthrough_fork

# Compares the /dev/fuse and io_uring transports on the host. Unpinned by default; on
# multi-socket hosts pass --client-cpus/--server-cpus, see README "Benchmarking"
bench:
	cargo run --release -p fuser-tests -- transport-bench

test: pre mount_tests pjdfs_tests xfstests
	cargo test

test_macos: pre
	cargo doc --all --no-deps
	cargo test --all --all-targets --features=libfuse2 -- --skip=mnt::test::mount_unmount
	cargo run -p fuser-tests -- macos-mount
	./tests/macos_pjdfs.sh
