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

- `wasm`
   >
         wasm-pack build \
            --scope premai-io \ # repo owner
            prem-rs

## TODOs

- use `vcpkg` for cross compilation?
