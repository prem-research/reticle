.PHONY: nvidia-cpp-sdk bins wasm clean sysroot attestation-server-image clean-sysroot

CMAKE_JOBS ?= $$(nproc)
DOCKER ?= docker
ATTESTATION_SERVER_IMAGE ?= attestation-server:local

LOCAL_SYSROOT := sysroot
LOCAL_SYSROOT_STAMP := $(LOCAL_SYSROOT)/.complete
SYSROOT ?= $(abspath $(LOCAL_SYSROOT))
NVAT_SDK_DIR ?= $(SYSROOT)/.nvidia-attestation-sdk

nvidia-cpp-sdk:
	mkdir -p "$(SYSROOT)"
	git clone \
		-b main \
		--depth 1 \
		https://github.com/coval3nte/attestation-sdk \
		"$(NVAT_SDK_DIR)" || true \
	&& cd "$(NVAT_SDK_DIR)" \
	&& git fetch --depth 1 origin 6d04df39fdf2e7ad5e7baef6b94f20ab5e9385b0 \
	&& git checkout 6d04df39fdf2e7ad5e7baef6b94f20ab5e9385b0 \
	&& cd nv-attestation-sdk-cpp \
	&& rm -rf build \
	&& PKG_CONFIG_SYSROOT_DIR= \
	PKG_CONFIG_PATH="$(SYSROOT)/lib/pkgconfig:$(SYSROOT)/share/pkgconfig" \
	cmake -S . -B build \
		-DUSE_SYSTEM_DEPS=ON \
		-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/toolchain-x86_64-linux-gnu.cmake \
		-DCMAKE_INSTALL_PREFIX="$(SYSROOT)" \
		-DCMAKE_FIND_LIBRARY_SUFFIXES=".a" \
		-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=$${CMAKE_FIND_ROOT_PATH_MODE_INCLUDE:-} \
	&& cmake --build build -j$(CMAKE_JOBS) \
	&& cmake --install build --strip

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

sysroot: $(LOCAL_SYSROOT_STAMP)

$(LOCAL_SYSROOT_STAMP): .devcontainer/Dockerfile Makefile
	rm -rf "$(LOCAL_SYSROOT)"
	$(DOCKER) build \
		--file .devcontainer/Dockerfile \
		--target sysroot-export \
		--output type=local,dest=$(LOCAL_SYSROOT) \
		.
	find "$(LOCAL_SYSROOT)" -name '*.pc' -exec \
		sed -i 's|/x86_64-sysroot|$${pcfiledir}/../..|g' {} +
	$(MAKE) nvidia-cpp-sdk SYSROOT="$(abspath $(LOCAL_SYSROOT))"
	touch "$@"

attestation-server-image: $(LOCAL_SYSROOT_STAMP)
	env -u SYSROOT \
		PKG_CONFIG_SYSROOT_DIR= \
		PKG_CONFIG_PATH="$(abspath $(LOCAL_SYSROOT))/lib/pkgconfig:$(abspath $(LOCAL_SYSROOT))/share/pkgconfig" \
		NVAT_INCLUDE_DIR="$(abspath $(LOCAL_SYSROOT))/include" \
		NVAT_LIBRARY="$(abspath $(LOCAL_SYSROOT))/lib" \
		RUSTFLAGS="-L$(abspath $(LOCAL_SYSROOT))/lib -lssl -lcrypto" \
		cargo build --release -p attestation-server
	$(DOCKER) build \
		--file attestation-server/Dockerfile \
		--build-arg SYSROOT=./$(LOCAL_SYSROOT) \
		--tag $(ATTESTATION_SERVER_IMAGE) \
		.

clean-sysroot:
	rm -rf "$(LOCAL_SYSROOT)"

clean:
	rm -rf \
		attestation-sdk \
		target
