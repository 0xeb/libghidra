// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::models;
use crate::proto::libghidra as pb;

// -- Enum conversions --------------------------------------------------------

impl From<models::ShutdownPolicy> for i32 {
    fn from(p: models::ShutdownPolicy) -> i32 {
        match p {
            models::ShutdownPolicy::Unspecified => 0,
            models::ShutdownPolicy::Save => 1,
            models::ShutdownPolicy::Discard => 2,
            models::ShutdownPolicy::None => 3,
        }
    }
}

impl From<models::CommentKind> for i32 {
    fn from(k: models::CommentKind) -> i32 {
        match k {
            models::CommentKind::Unspecified => 0,
            models::CommentKind::Eol => 1,
            models::CommentKind::Pre => 2,
            models::CommentKind::Post => 3,
            models::CommentKind::Plate => 4,
            models::CommentKind::Repeatable => 5,
        }
    }
}

impl From<i32> for models::CommentKind {
    fn from(v: i32) -> Self {
        match v {
            1 => Self::Eol,
            2 => Self::Pre,
            3 => Self::Post,
            4 => Self::Plate,
            5 => Self::Repeatable,
            _ => Self::Unspecified,
        }
    }
}

// -- Record conversions (proto → model) --------------------------------------

impl From<pb::FunctionRecord> for models::FunctionRecord {
    fn from(r: pb::FunctionRecord) -> Self {
        Self {
            entry_address: r.entry_address,
            name: r.name,
            start_address: r.start_address,
            end_address: r.end_address,
            size: r.size,
            namespace_name: r.namespace_name,
            prototype: r.prototype,
            is_thunk: r.is_thunk,
            parameter_count: r.parameter_count,
        }
    }
}

impl From<pb::SymbolRecord> for models::SymbolRecord {
    fn from(r: pb::SymbolRecord) -> Self {
        Self {
            symbol_id: r.symbol_id,
            address: r.address,
            name: r.name,
            full_name: r.full_name,
            r#type: r.r#type,
            namespace_name: r.namespace_name,
            source: r.source,
            is_primary: r.is_primary,
            is_external: r.is_external,
            is_dynamic: r.is_dynamic,
        }
    }
}

impl From<pb::XrefRecord> for models::XrefRecord {
    fn from(r: pb::XrefRecord) -> Self {
        Self {
            from_address: r.from_address,
            to_address: r.to_address,
            operand_index: r.operand_index,
            ref_type: r.ref_type,
            is_primary: r.is_primary,
            source: r.source,
            symbol_id: r.symbol_id,
            is_external: r.is_external,
            is_memory: r.is_memory,
            is_flow: r.is_flow,
        }
    }
}

impl From<pb::TypeRecord> for models::TypeRecord {
    fn from(r: pb::TypeRecord) -> Self {
        Self {
            type_id: r.type_id,
            name: r.name,
            path_name: r.path_name,
            category_path: r.category_path,
            display_name: r.display_name,
            kind: r.kind,
            length: r.length,
            is_not_yet_defined: r.is_not_yet_defined,
            source_archive: r.source_archive,
            universal_id: r.universal_id,
        }
    }
}

impl From<pb::TypeAliasRecord> for models::TypeAliasRecord {
    fn from(r: pb::TypeAliasRecord) -> Self {
        Self {
            type_id: r.type_id,
            path_name: r.path_name,
            name: r.name,
            target_type: r.target_type,
            declaration: r.declaration,
        }
    }
}

impl From<pb::TypeUnionRecord> for models::TypeUnionRecord {
    fn from(r: pb::TypeUnionRecord) -> Self {
        Self {
            type_id: r.type_id,
            path_name: r.path_name,
            name: r.name,
            size: r.size,
            declaration: r.declaration,
        }
    }
}

impl From<pb::TypeEnumRecord> for models::TypeEnumRecord {
    fn from(r: pb::TypeEnumRecord) -> Self {
        Self {
            type_id: r.type_id,
            path_name: r.path_name,
            name: r.name,
            width: r.width,
            is_signed: r.signed,
            declaration: r.declaration,
        }
    }
}

impl From<pb::TypeEnumMemberRecord> for models::TypeEnumMemberRecord {
    fn from(r: pb::TypeEnumMemberRecord) -> Self {
        Self {
            type_id: r.type_id,
            type_path_name: r.type_path_name,
            type_name: r.type_name,
            ordinal: r.ordinal,
            name: r.name,
            value: r.value,
        }
    }
}

impl From<pb::TypeMemberRecord> for models::TypeMemberRecord {
    fn from(r: pb::TypeMemberRecord) -> Self {
        Self {
            parent_type_id: r.parent_type_id,
            parent_type_path_name: r.parent_type_path_name,
            parent_type_name: r.parent_type_name,
            ordinal: r.ordinal,
            name: r.name,
            member_type: r.member_type,
            offset: r.offset,
            size: r.size,
        }
    }
}

impl From<pb::ParameterRecord> for models::ParameterRecord {
    fn from(r: pb::ParameterRecord) -> Self {
        Self {
            ordinal: r.ordinal,
            name: r.name,
            data_type: r.data_type,
            formal_data_type: r.formal_data_type,
            is_auto_parameter: r.is_auto_parameter,
            is_forced_indirect: r.is_forced_indirect,
        }
    }
}

impl From<pb::FunctionSignatureRecord> for models::FunctionSignatureRecord {
    fn from(r: pb::FunctionSignatureRecord) -> Self {
        Self {
            function_entry_address: r.function_entry_address,
            function_name: r.function_name,
            prototype: r.prototype,
            return_type: r.return_type,
            has_var_args: r.has_var_args,
            calling_convention: r.calling_convention,
            parameters: r.parameters.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<pb::DecompileRecord> for models::DecompilationRecord {
    fn from(r: pb::DecompileRecord) -> Self {
        Self {
            function_entry_address: r.function_entry_address,
            function_name: r.function_name,
            prototype: r.prototype,
            pseudocode: r.pseudocode,
            completed: r.completed,
            is_fallback: r.is_fallback,
            error_message: r.error_message,
            locals: r.locals.into_iter().map(Into::into).collect(),
            tokens: r.tokens.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<pb::DecompileLocalKind> for models::DecompileLocalKind {
    fn from(kind: pb::DecompileLocalKind) -> Self {
        match kind {
            pb::DecompileLocalKind::Param => Self::Param,
            pb::DecompileLocalKind::Local => Self::Local,
            pb::DecompileLocalKind::Temp => Self::Temp,
            pb::DecompileLocalKind::Unspecified => Self::Unspecified,
        }
    }
}

impl From<pb::DecompileLocalRecord> for models::DecompileLocalRecord {
    fn from(r: pb::DecompileLocalRecord) -> Self {
        Self {
            local_id: r.local_id,
            kind: pb::DecompileLocalKind::try_from(r.kind)
                .unwrap_or(pb::DecompileLocalKind::Unspecified)
                .into(),
            name: r.name,
            data_type: r.data_type,
            storage: r.storage,
            ordinal: r.ordinal,
        }
    }
}

impl From<pb::DecompileTokenKind> for models::DecompileTokenKind {
    fn from(kind: pb::DecompileTokenKind) -> Self {
        match kind {
            pb::DecompileTokenKind::Keyword => Self::Keyword,
            pb::DecompileTokenKind::Comment => Self::Comment,
            pb::DecompileTokenKind::Type => Self::Type,
            pb::DecompileTokenKind::Function => Self::Function,
            pb::DecompileTokenKind::Variable => Self::Variable,
            pb::DecompileTokenKind::Const => Self::Const,
            pb::DecompileTokenKind::Parameter => Self::Parameter,
            pb::DecompileTokenKind::Global => Self::Global,
            pb::DecompileTokenKind::Default => Self::Default,
            pb::DecompileTokenKind::Error => Self::Error,
            pb::DecompileTokenKind::Special => Self::Special,
            pb::DecompileTokenKind::Unspecified => Self::Unspecified,
        }
    }
}

impl From<pb::DecompileTokenRecord> for models::DecompileTokenRecord {
    fn from(r: pb::DecompileTokenRecord) -> Self {
        Self {
            text: r.text,
            kind: pb::DecompileTokenKind::try_from(r.kind)
                .unwrap_or(pb::DecompileTokenKind::Unspecified)
                .into(),
            line_number: r.line_number,
            column_offset: r.column_offset,
            var_name: r.var_name,
            var_type: r.var_type,
            var_storage: r.var_storage,
        }
    }
}

impl From<pb::SwitchCaseRecord> for models::SwitchCaseRecord {
    fn from(r: pb::SwitchCaseRecord) -> Self {
        Self {
            value: r.value,
            target_address: r.target_address,
        }
    }
}

impl From<pb::SwitchTableRecord> for models::SwitchTableRecord {
    fn from(r: pb::SwitchTableRecord) -> Self {
        Self {
            function_entry: r.function_entry,
            switch_address: r.switch_address,
            case_count: r.case_count,
            cases: r.cases.into_iter().map(Into::into).collect(),
            default_address: r.default_address,
        }
    }
}

impl From<pb::DominatorRecord> for models::DominatorRecord {
    fn from(r: pb::DominatorRecord) -> Self {
        Self {
            function_entry: r.function_entry,
            block_address: r.block_address,
            idom_address: r.idom_address,
            depth: r.depth,
            is_entry: r.is_entry,
        }
    }
}

impl From<pb::PostDominatorRecord> for models::PostDominatorRecord {
    fn from(r: pb::PostDominatorRecord) -> Self {
        Self {
            function_entry: r.function_entry,
            block_address: r.block_address,
            ipdom_address: r.ipdom_address,
            depth: r.depth,
            is_exit: r.is_exit,
        }
    }
}

impl From<pb::LoopRecord> for models::LoopRecord {
    fn from(r: pb::LoopRecord) -> Self {
        Self {
            function_entry: r.function_entry,
            header_address: r.header_address,
            back_edge_source: r.back_edge_source,
            loop_kind: r.loop_kind,
            block_count: r.block_count,
            depth: r.depth,
        }
    }
}

impl From<pb::InstructionRecord> for models::InstructionRecord {
    fn from(r: pb::InstructionRecord) -> Self {
        Self {
            address: r.address,
            mnemonic: r.mnemonic,
            operand_text: r.operand_text,
            disassembly: r.disassembly,
            length: r.length,
        }
    }
}

impl From<pb::CommentRecord> for models::CommentRecord {
    fn from(r: pb::CommentRecord) -> Self {
        Self {
            address: r.address,
            kind: models::CommentKind::from(r.kind),
            text: r.text,
        }
    }
}

impl From<pb::DataItemRecord> for models::DataItemRecord {
    fn from(r: pb::DataItemRecord) -> Self {
        Self {
            address: r.address,
            end_address: r.end_address,
            name: r.name,
            data_type: r.data_type,
            size: r.size,
            value_repr: r.value_repr,
        }
    }
}

impl From<pb::BookmarkRecord> for models::BookmarkRecord {
    fn from(r: pb::BookmarkRecord) -> Self {
        Self {
            address: r.address,
            r#type: r.r#type,
            category: r.category,
            comment: r.comment,
        }
    }
}

impl From<pb::BreakpointRecord> for models::BreakpointRecord {
    fn from(r: pb::BreakpointRecord) -> Self {
        Self {
            address: r.address,
            enabled: r.enabled,
            kind: r.kind,
            size: r.size,
            condition: r.condition,
            group: r.group,
        }
    }
}

impl From<pb::MemoryBlockRecord> for models::MemoryBlockRecord {
    fn from(r: pb::MemoryBlockRecord) -> Self {
        Self {
            name: r.name,
            start_address: r.start_address,
            end_address: r.end_address,
            size: r.size,
            is_read: r.is_read,
            is_write: r.is_write,
            is_execute: r.is_execute,
            is_volatile: r.is_volatile,
            is_initialized: r.is_initialized,
            source_name: r.source_name,
            comment: r.comment,
        }
    }
}

impl From<pb::BasicBlockRecord> for models::BasicBlockRecord {
    fn from(r: pb::BasicBlockRecord) -> Self {
        Self {
            function_entry: r.function_entry,
            start_address: r.start_address,
            end_address: r.end_address,
            in_degree: r.in_degree,
            out_degree: r.out_degree,
        }
    }
}

impl From<pb::CfgEdgeRecord> for models::CFGEdgeRecord {
    fn from(r: pb::CfgEdgeRecord) -> Self {
        Self {
            function_entry: r.function_entry,
            src_block_start: r.src_block_start,
            dst_block_start: r.dst_block_start,
            edge_kind: r.edge_kind,
        }
    }
}

impl From<pb::DefinedStringRecord> for models::DefinedStringRecord {
    fn from(r: pb::DefinedStringRecord) -> Self {
        Self {
            address: r.address,
            value: r.value,
            length: r.length,
            data_type: r.data_type,
            encoding: r.encoding,
        }
    }
}

impl From<pb::Capability> for models::Capability {
    fn from(r: pb::Capability) -> Self {
        Self {
            id: r.id,
            status: r.status,
            note: r.note,
        }
    }
}

impl From<pb::FunctionTagRecord> for models::FunctionTagRecord {
    fn from(r: pb::FunctionTagRecord) -> Self {
        Self {
            name: r.name,
            comment: r.comment,
        }
    }
}

impl From<pb::FunctionTagMappingRecord> for models::FunctionTagMappingRecord {
    fn from(r: pb::FunctionTagMappingRecord) -> Self {
        Self {
            function_entry: r.function_entry,
            tag_name: r.tag_name,
        }
    }
}
