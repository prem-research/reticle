.PHONY: nvidia-cpp-sdk bins wasm

nvidia-cpp-sdk:
	git clone \
		-b main \
		--depth 1 \
		https://github.com/coval3nte/attestation-sdk \
		attestation-sdk || true \
	&& cd attestation-sdk \
	&& git fetch --depth 1 origin 635438db5bede7ae9fb4e178236330e6c50fb48b \
	&& git checkout 635438db5bede7ae9fb4e178236330e6c50fb48b \
	&& cd nv-attestation-sdk-cpp \
	&& rm -rf build \
	&& cmake -S . -B build \
		-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/toolchain-x86_64-linux-gnu.cmake \
		-DCMAKE_INSTALL_PREFIX=$${SYSROOT:-/usr/local} \
		-DCMAKE_FIND_LIBRARY_SUFFIXES=".a" \
		-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=$${CMAKE_FIND_ROOT_PATH_MODE_INCLUDE:-} \
	&& cmake --build build -j$(nproc) \
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
	wasm-pack build prem-rs

clean:
	rm -rf \
		attestation-sdk \
		target
