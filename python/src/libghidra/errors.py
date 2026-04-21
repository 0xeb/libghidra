# Copyright (c) 2024-2026 Elias Bachaalany
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

"""Error types for the libghidra Python client."""

from __future__ import annotations

from enum import Enum


class ErrorCode(Enum):
    """Semantic error codes matching the RPC error protocol."""

    CONNECTION_FAILED = "connection_failed"
    TIMEOUT = "timeout"
    TRANSPORT_ERROR = "transport_error"
    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    TOO_MANY_REQUESTS = "too_many_requests"
    INTERNAL_ERROR = "internal_error"
    BAD_GATEWAY = "bad_gateway"
    SERVICE_UNAVAILABLE = "service_unavailable"
    GATEWAY_TIMEOUT = "gateway_timeout"
    HTTP_ERROR = "http_error"
    ENCODE_ERROR = "encode_error"
    PARSE_ERROR = "parse_error"
    API_ERROR = "api_error"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    CONFIG_ERROR = "config_error"
    OTHER = "other"

    def is_retryable(self) -> bool:
        return self in {
            ErrorCode.CONNECTION_FAILED,
            ErrorCode.TIMEOUT,
            ErrorCode.TOO_MANY_REQUESTS,
            ErrorCode.INTERNAL_ERROR,
            ErrorCode.BAD_GATEWAY,
            ErrorCode.SERVICE_UNAVAILABLE,
            ErrorCode.GATEWAY_TIMEOUT,
        }

    @staticmethod
    def from_http_status(status: int) -> ErrorCode:
        return {
            400: ErrorCode.BAD_REQUEST,
            401: ErrorCode.UNAUTHORIZED,
            403: ErrorCode.FORBIDDEN,
            404: ErrorCode.NOT_FOUND,
            409: ErrorCode.CONFLICT,
            429: ErrorCode.TOO_MANY_REQUESTS,
            500: ErrorCode.INTERNAL_ERROR,
            502: ErrorCode.BAD_GATEWAY,
            503: ErrorCode.SERVICE_UNAVAILABLE,
            504: ErrorCode.GATEWAY_TIMEOUT,
        }.get(status, ErrorCode.HTTP_ERROR)

    @staticmethod
    def from_rpc_code(code: str) -> ErrorCode:
        try:
            return ErrorCode(code)
        except ValueError:
            return ErrorCode.OTHER


class GhidraError(Exception):
    """Exception raised by GhidraClient on RPC or transport errors."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"{code.value}: {message}")
