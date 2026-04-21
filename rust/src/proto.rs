// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#[allow(dead_code)]
pub mod libghidra {
    include!(concat!(env!("OUT_DIR"), "/libghidra.rs"));
}

pub use self::libghidra as pb;

use prost::Message;

pub fn pack_any<M: Message>(msg: &M, type_name: &str) -> prost_types::Any {
    prost_types::Any {
        type_url: format!("type.googleapis.com/{}", type_name),
        value: msg.encode_to_vec(),
    }
}

pub fn unpack_any<M: Message + Default>(any: &prost_types::Any) -> Result<M, prost::DecodeError> {
    M::decode(any.value.as_slice())
}
