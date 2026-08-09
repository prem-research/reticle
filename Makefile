.PHONY: nvidia-cpp-sdk bins wasm clean attestation-server-image clean-sysroot

CMAKE_JOBS ?= $$(nproc)
DOCKER ?= docker
ATTESTATION_SERVER_IMAGE ?= attestation-server:local
SYSROOT ?= /x86_64-sysroot

LOCAL_SYSROOT := sysroot
LOCAL_SYSROOT_STAMP := $(LOCAL_SYSROOT)/.complete

nvidia-cpp-sdk:
	git clone \
		-b main \
		--depth 1 \
		https://github.com/coval3nte/attestation-sdk \
		attestation-sdk || true \
	&& cd attestation-sdk \
	&& git fetch --depth 1 origin 6d04df39fdf2e7ad5e7baef6b94f20ab5e9385b0 \
	&& git checkout 6d04df39fdf2e7ad5e7baef6b94f20ab5e9385b0 \
	&& cd nv-attestation-sdk-cpp \
	&& rm -rf build \
	&& cmake -S . -B build \
		-DUSE_SYSTEM_DEPS=ON \
		-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/toolchain-x86_64-linux-gnu.cmake \
		-DCMAKE_INSTALL_PREFIX=$${SYSROOT:-/usr/local} \
		-DCMAKE_FIND_LIBRARY_SUFFIXES=".a" \
		-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=$${CMAKE_FIND_ROOT_PATH_MODE_INCLUDE:-} \
	&& cmake --build build -j$(CMAKE_JOBS) \
	&& sudo cmake --install build --strip \
	&& sudo ldconfig

PACKAGE ?=
FEATURES ?=

bins:
	# tmp fix
	#([ ! -f /usr/local/include/nvat.h ] && sudo cp $${SYSROOT:-/usr/local}/include/nvat.h /usr/local/include) || true

	cargo build --target x86_64-unknown-linux-gnu --release \
		$(if $(PACKAGE),-p $(PACKAGE),) \
		$(if $(FEATURES),--no-default-features --features "$(FEATURES)",)

	# TODO: fix
	#cp $${SYSROOT:-/usr/local}/lib/libnvat.so.1.1.0 $(CURDIR)

wasm:
	wasm-pack build reticle

$(LOCAL_SYSROOT_STAMP):
	@test -d "$(SYSROOT)/lib" || { \
		echo "SYSROOT library directory not found: $(SYSROOT)/lib" >&2; \
		exit 1; \
	}
	mkdir -p $(LOCAL_SYSROOT)/lib
	cp -a "$(SYSROOT)/lib/." $(LOCAL_SYSROOT)/lib/
	touch $@

attestation-server-image: $(LOCAL_SYSROOT_STAMP)
	env -u SYSROOT \
		RUSTFLAGS="-L$(SYSROOT)/lib -lssl -lcrypto" \
		cargo build --release -p attestation-server
	$(DOCKER) build \
		--file attestation-server/Dockerfile \
		--build-arg SYSROOT=./$(LOCAL_SYSROOT) \
		--tag $(ATTESTATION_SERVER_IMAGE) \
		.

clean-sysroot:
	rm -rf $(LOCAL_SYSROOT)

clean:
	rm -rf \
		attestation-sdk \
		target
