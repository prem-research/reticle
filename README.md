## build

- `nvat-rs`
   > 
         cmake -S . -B build # -DCMAKE_TOOLCHAIN_FILE=toolchain-x86_64-linux-gnu.cmake 
         cmake --build build -j$(nproc)
         cmake --install build --strip
         sudo ldconfig

- `bins`
   >
         cargo build --target x86_64-unknown-linux-gnu --release
   
   * need libnvat.so

- `wasm`
   >
         wasm-pack build \
            --scope premai-io \ # repo owner
            prem-rs

## NodeJS `prem-rs` Testing

* use _npm_ / _bun_ link (`npm link`) in [`./prem-rs/pkg`](./prem-rs/pkg)
* link the local package in an [example](./examples) using `bun link @premAI-io/prem-rs`

## TODOs

- use `vcpkg` for cross compilation?
- chroot with all deps ($SYSROOT)
