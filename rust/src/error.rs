// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
    ConfigError,
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
            "NOT_SUPPORTED" => Self::NotSupported,
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
            Self::NotSupported => "NOT_SUPPORTED",
            Self::ConfigError => "config_error",
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
