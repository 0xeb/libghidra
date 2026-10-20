// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    ConnectionFailed,
    Timeout,
    TransportError,
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    TooManyRequests,
    InternalError,
    BadGateway,
    ServiceUnavailable,
    GatewayTimeout,
    HttpError,
    EncodeError,
    ParseError,
    ApiError,
    NotSupported,
    /// No program is open: the session has nothing to read (`not_loaded`).
    /// A missing item is not an error -- the record comes back absent.
    NotLoaded,
    ConfigError,
    // The rest of the RPC vocabulary documented on RpcResponse.error_code
    // (rpc.proto). A write either has its effect or fails with one of these.
    /// No memory block contains the address (`unmapped_address`).
    UnmappedAddress,
    /// The request is malformed or names the wrong kind of thing (`invalid_argument`).
    InvalidArgument,
    /// The name a create or rename asks for is taken (`duplicate_name`).
    DuplicateName,
    /// The block exists but holds no bytes (`uninitialized_memory`).
    UninitializedMemory,
    /// The host is busy with conflicting state (`access_conflict`).
    AccessConflict,
    /// An analysis job owns the program (`analysis_running`).
    AnalysisRunning,
    /// The request or job was cancelled (`cancelled`).
    Cancelled,
    /// The method name is not an RPC (`unknown_method`).
    UnknownMethod,
    /// The payload does not decode as the method's request (`invalid_payload`).
    InvalidPayload,
    /// A type named as an argument does not resolve (`unknown_type`).
    UnknownType,
    Other(String),
}

impl ErrorCode {
    pub fn from_http_status(status: u16) -> Self {
        match status {
            400 => Self::BadRequest,
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            404 => Self::NotFound,
            409 => Self::Conflict,
            429 => Self::TooManyRequests,
            500 => Self::InternalError,
            502 => Self::BadGateway,
            503 => Self::ServiceUnavailable,
            504 => Self::GatewayTimeout,
            _ => Self::HttpError,
        }
    }

    pub fn from_rpc_code(code: &str) -> Self {
        match code {
            "bad_request" => Self::BadRequest,
            "unauthorized" => Self::Unauthorized,
            "forbidden" => Self::Forbidden,
            "not_found" => Self::NotFound,
            "conflict" => Self::Conflict,
            "too_many_requests" => Self::TooManyRequests,
            "internal_error" => Self::InternalError,
            "bad_gateway" => Self::BadGateway,
            "service_unavailable" => Self::ServiceUnavailable,
            "gateway_timeout" => Self::GatewayTimeout,
            "connection_failed" => Self::ConnectionFailed,
            "timeout" => Self::Timeout,
            "transport_error" => Self::TransportError,
            "encode_error" => Self::EncodeError,
            "parse_error" => Self::ParseError,
            "config_error" => Self::ConfigError,
            "api_error" => Self::ApiError,
            "not_supported" => Self::NotSupported,
            "not_loaded" => Self::NotLoaded,
            "unmapped_address" => Self::UnmappedAddress,
            "invalid_argument" => Self::InvalidArgument,
            "duplicate_name" => Self::DuplicateName,
            "uninitialized_memory" => Self::UninitializedMemory,
            "access_conflict" => Self::AccessConflict,
            "analysis_running" => Self::AnalysisRunning,
            "cancelled" => Self::Cancelled,
            "unknown_method" => Self::UnknownMethod,
            "invalid_payload" => Self::InvalidPayload,
            "unknown_type" => Self::UnknownType,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::ConnectionFailed => "connection_failed",
            Self::Timeout => "timeout",
            Self::TransportError => "transport_error",
            Self::BadRequest => "bad_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::TooManyRequests => "too_many_requests",
            Self::InternalError => "internal_error",
            Self::BadGateway => "bad_gateway",
            Self::ServiceUnavailable => "service_unavailable",
            Self::GatewayTimeout => "gateway_timeout",
            Self::HttpError => "http_error",
            Self::EncodeError => "encode_error",
            Self::ParseError => "parse_error",
            Self::ApiError => "api_error",
            Self::NotSupported => "not_supported",
            Self::NotLoaded => "not_loaded",
            Self::ConfigError => "config_error",
            Self::UnmappedAddress => "unmapped_address",
            Self::InvalidArgument => "invalid_argument",
            Self::DuplicateName => "duplicate_name",
            Self::UninitializedMemory => "uninitialized_memory",
            Self::AccessConflict => "access_conflict",
            Self::AnalysisRunning => "analysis_running",
            Self::Cancelled => "cancelled",
            Self::UnknownMethod => "unknown_method",
            Self::InvalidPayload => "invalid_payload",
            Self::UnknownType => "unknown_type",
            Self::Other(s) => s.as_str(),
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::ConnectionFailed
                | Self::Timeout
                | Self::TooManyRequests
                | Self::InternalError
                | Self::BadGateway
                | Self::ServiceUnavailable
                | Self::GatewayTimeout
        )
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    pub code: ErrorCode,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

impl Error {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
