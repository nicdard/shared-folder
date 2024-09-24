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
use mls::{AddProposalMessages, ApplicationMsgAuthenticatedData};
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

        /// CGKA.Init(uid).
        #[wasm_bindgen(js_name = mlsInitClient)]
        pub async fn mls_init_client(uid: &[u8]) -> Result<(), String> {
            set_panic_hook();
            mls::get_client(uid)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }

        // CGKA.Create(gamma)
        #[wasm_bindgen(js_name = mlsCgkaInit)]
        pub async fn mls_cgka_init(uid: &[u8], group_id: &[u8]) -> Result<(), String> {
            set_panic_hook();
            mls::cgka_init(uid, group_id)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }

        /// Generate a KeyPackage message [`MlsMessage`]
        #[wasm_bindgen(js_name = mlsGenerateKeyPackage)]
        pub async fn mls_generate_key_package(uid: &[u8]) -> Result<Vec<u8>, String> {
            mls::cgka_generate_key_package(uid)
                .await
                .map_err(|e| e.to_string())
        }

        /// Propose the addition of a new user given using its [`KeyPackage`] (given as an [`MlsMessage`]).
        #[wasm_bindgen(js_name = mlsCgkaAddProposal)]
        pub async fn mls_cgka_add_proposal(uid: &[u8], group_id: &[u8], key_package_raw_msg: &[u8]) -> Result<AddProposalMessages, String> {
            mls::cgka_add_proposal(uid, group_id, key_package_raw_msg)
                .await
                .map_err(|e| e.to_string())
        }

        #[wasm_bindgen(js_name = mlsCgkaJoinGroup)]
        pub async fn mls_cgka_join_group(uid: &[u8], welcome_msg: &[u8]) -> Result<Vec<u8>, String> {
            mls::cgka_join_group(uid, welcome_msg)
                .await
                .map_err(|e| e.to_string())
        }

        /// Apply any pending commit from the group status.
        #[wasm_bindgen(js_name = mlsCgkaApplyPendingCommit)]
        pub async fn mls_cgka_apply_pending_commit(uid: &[u8], group_id: &[u8]) -> Result<Vec<u8>, String> {
            mls::cgka_apply_pending_commit(uid, group_id)
                .await
                .map_err(|e| e.to_string())
        }

        /// Remove any pending commit from the group status.
        #[wasm_bindgen(js_name = mlsCgkaDeletePendingCommit)]
        pub async fn mls_cgka_delete_pending_commit(uid: &[u8], group_id: &[u8]) -> Result<(), String> {
            mls::cgka_delete_pending_commit(uid, group_id)
                .await
                .map_err(|e| e.to_string())
        }

        #[wasm_bindgen(js_name = mlsPrepareAppMsg)]
        pub async fn mls_prepare_app_msg(uid: &[u8], group_id: &[u8], app_msg: &[u8], ad: ApplicationMsgAuthenticatedData) -> Result<Vec<u8>, String> {
            mls::cgka_prepare_application_msg(uid, group_id, app_msg, ad)
                .await
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
