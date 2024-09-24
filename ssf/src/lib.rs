// Copyright (C) 2024 Nicola Dardanis <nicdard@gmail.com>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.
//
use cfg_if::cfg_if;
use mls_rs::{ExtensionList, GroupStateStorage};
use utils::set_panic_hook;
use wasm_bindgen::prelude::*;

mod mls;
mod utils;

// Less efficient allocator than the default one which however is super small, only 1K in code size (compared to ~10K)
cfg_if! {
    if #[cfg(feature = "wee_alloc")] {
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(a: &str);
}

cfg_if! {
    if #[cfg(all(mls_build_async))] {
        // CGKA.Init(uid), we also need to pass the identity of the client creating the group.
        #[wasm_bindgen(js_name = mlsCgkaInit)]
        pub async fn mls_cgka_init(identity: &[u8], uid: &[u8]) -> Result<(), String> {
            mls::cgka_init(identity, uid)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }

        // Exposed for test purposes.
        #[wasm_bindgen]
        pub async fn mls_example() -> () {
            set_panic_hook();
            let _ = mls::get_client(b"Alice").await;
        }
    }
}
