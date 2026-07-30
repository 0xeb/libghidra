// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

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
