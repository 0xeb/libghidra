// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Pagination helpers for auto-fetching all pages from a paginated list RPC.

use crate::error::Result;

const DEFAULT_PAGE_SIZE: i32 = 100;

/// Auto-paginating iterator that fetches pages on demand.
///
/// Created via [`Paginator::new`] with a closure that calls a list method with
/// `(limit, offset)` and returns a `Vec<T>` of items from the response.
///
/// # Example
///
/// ```no_run
/// use libghidra as ghidra;
/// use ghidra::paginate::Paginator;
///
/// let client = ghidra::connect("http://127.0.0.1:18080");
/// let all_funcs: Vec<_> = Paginator::new(|limit, offset| {
///     let resp = client.list_functions(0, u64::MAX, limit, offset)?;
///     Ok(resp.functions)
/// }).collect::<Result<Vec<_>, _>>()?.into_iter().flatten().collect();
/// # Ok::<(), ghidra::Error>(())
/// ```
pub struct Paginator<T, F>
where
    F: FnMut(i32, i32) -> Result<Vec<T>>,
{
    fetch: F,
    page_size: i32,
    offset: i32,
    done: bool,
}

impl<T, F> Paginator<T, F>
where
    F: FnMut(i32, i32) -> Result<Vec<T>>,
{
    /// Create a paginator with the default page size (100).
    ///
    /// The `fetch` closure receives `(limit, offset)` and should return the
    /// items from one page.
    pub fn new(fetch: F) -> Self {
        Self {
            fetch,
            page_size: DEFAULT_PAGE_SIZE,
            offset: 0,
            done: false,
        }
    }

    /// Override the page size (default: 100).
    pub fn page_size(mut self, size: i32) -> Self {
        self.page_size = size.max(1);
        self
    }
}

impl<T, F> Iterator for Paginator<T, F>
where
    F: FnMut(i32, i32) -> Result<Vec<T>>,
{
    type Item = Result<Vec<T>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        match (self.fetch)(self.page_size, self.offset) {
            Ok(items) => {
                let count = items.len() as i32;
                self.offset += count;
                if count < self.page_size {
                    self.done = true;
                }
                if count == 0 {
                    return None;
                }
                Some(Ok(items))
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// Collect all items from a paginated list RPC into a single `Vec`.
///
/// Convenience function that creates a [`Paginator`] and drains all pages.
///
/// # Example
///
/// ```no_run
/// use libghidra as ghidra;
/// use ghidra::paginate::fetch_all;
///
/// let client = ghidra::connect("http://127.0.0.1:18080");
/// let all_funcs = fetch_all(|limit, offset| {
///     let resp = client.list_functions(0, u64::MAX, limit, offset)?;
///     Ok(resp.functions)
/// })?;
/// # Ok::<(), ghidra::Error>(())
/// ```
pub fn fetch_all<T, F>(fetch: F) -> Result<Vec<T>>
where
    F: FnMut(i32, i32) -> Result<Vec<T>>,
{
    let mut all = Vec::new();
    for page in Paginator::new(fetch) {
        all.extend(page?);
    }
    Ok(all)
}
