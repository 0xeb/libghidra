// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import libghidra.host.contract.SessionContract;

/**
 * Persists {@code perf_benchmarks} rows inside the program database using program
 * {@link Options}. Program options are part of the program's persistent state, so
 * they are written to disk by {@code program.save()} (the SaveProgram RPC) and are
 * reverted by {@code program.undo()} (the DiscardProgram RPC) — exactly the
 * populate-and-persist semantics the SQL table needs.
 *
 * <p>Storage layout (all under the {@link #OPTIONS_CATEGORY} option group):
 * <ul>
 *   <li>{@code count} — number of stored records (int).</li>
 *   <li>{@code record.NNNN} — the NNNN-th record, serialized as a
 *       semicolon-delimited {@code key=value} string with every text field
 *       base64-url-encoded so an embedded delimiter cannot corrupt the record.</li>
 * </ul>
 *
 * <p>The class is a stateless collection of static helpers that operate on a live
 * program inside a caller-provided transaction; it never opens a transaction of
 * its own (mirroring {@code BreakpointBookmarkStore}).
 */
final class PerfBenchmarkStore {

	static final String OPTIONS_CATEGORY = "libghidra.PerfBenchmarks";
	private static final String COUNT_KEY = "count";
	private static final String RECORD_PREFIX = "record.";

	private PerfBenchmarkStore() {
	}

	static List<SessionContract.PerfBenchmarkRecord> all(Program program) {
		List<SessionContract.PerfBenchmarkRecord> out = new ArrayList<>();
		if (program == null) {
			return out;
		}
		Options options = program.getOptions(OPTIONS_CATEGORY);
		int count = Math.max(0, options.getInt(COUNT_KEY, 0));
		for (int i = 0; i < count; i++) {
			String encoded = options.getString(recordKey(i), "");
			if (encoded == null || encoded.isBlank()) {
				continue;
			}
			out.add(deserialize(encoded));
		}
		return out;
	}

	/**
	 * Upserts a record keyed on {@code bench_id}: any existing record(s) with the
	 * same bench_id are replaced by the new record (a re-run of a benchmark must
	 * not accumulate duplicate rows). Must be called inside an active program
	 * transaction.
	 */
	static void add(Program program, SessionContract.PerfBenchmarkRecord record) {
		if (program == null || record == null) {
			return;
		}
		List<SessionContract.PerfBenchmarkRecord> kept = allExcept(program, record.benchId());
		kept.add(record);
		rewrite(program, kept);
	}

	/**
	 * Removes every stored record whose bench_id equals {@code benchId}. Must be
	 * called inside an active program transaction. Returns the number of records
	 * that were removed.
	 */
	static int delete(Program program, String benchId) {
		if (program == null || benchId == null || benchId.isBlank()) {
			return 0;
		}
		List<SessionContract.PerfBenchmarkRecord> before = all(program);
		List<SessionContract.PerfBenchmarkRecord> kept = allExcept(program, benchId);
		int removed = before.size() - kept.size();
		if (removed > 0) {
			rewrite(program, kept);
		}
		return removed;
	}

	/**
	 * Removes every stored record. Must be called inside an active program
	 * transaction. Returns the number of records that were removed.
	 */
	static int clear(Program program) {
		if (program == null) {
			return 0;
		}
		Options options = program.getOptions(OPTIONS_CATEGORY);
		int count = Math.max(0, options.getInt(COUNT_KEY, 0));
		for (int i = 0; i < count; i++) {
			String key = recordKey(i);
			if (options.contains(key)) {
				options.removeOption(key);
			}
		}
		if (options.contains(COUNT_KEY)) {
			options.removeOption(COUNT_KEY);
		}
		return count;
	}

	/** All stored records except those whose bench_id equals {@code benchId}. */
	private static List<SessionContract.PerfBenchmarkRecord> allExcept(
			Program program, String benchId) {
		List<SessionContract.PerfBenchmarkRecord> kept = new ArrayList<>();
		for (SessionContract.PerfBenchmarkRecord row : all(program)) {
			if (row.benchId() != null && row.benchId().equals(benchId)) {
				continue;
			}
			kept.add(row);
		}
		return kept;
	}

	/**
	 * Replaces the whole store with {@code records} (clear + sequential rewrite).
	 * Must be called inside an active program transaction.
	 */
	private static void rewrite(Program program,
			List<SessionContract.PerfBenchmarkRecord> records) {
		clear(program);
		Options options = program.getOptions(OPTIONS_CATEGORY);
		int index = 0;
		for (SessionContract.PerfBenchmarkRecord row : records) {
			options.setString(recordKey(index), serialize(row));
			index++;
		}
		options.setInt(COUNT_KEY, index);
	}

	private static String recordKey(int index) {
		return String.format("%s%04d", RECORD_PREFIX, index);
	}

	private static String serialize(SessionContract.PerfBenchmarkRecord row) {
		StringBuilder sb = new StringBuilder();
		sb.append("bench_id=").append(encode(row.benchId()));
		sb.append(";query_family=").append(encode(row.queryFamily()));
		sb.append(";dataset_profile=").append(encode(row.datasetProfile()));
		sb.append(";cold_ms_p50=").append(Double.toString(row.coldMsP50()));
		sb.append(";cold_ms_p95=").append(Double.toString(row.coldMsP95()));
		sb.append(";warm_ms_p50=").append(Double.toString(row.warmMsP50()));
		sb.append(";warm_ms_p95=").append(Double.toString(row.warmMsP95()));
		sb.append(";throughput_qps=").append(Double.toString(row.throughputQps()));
		sb.append(";regression_pct=").append(Double.toString(row.regressionPct()));
		sb.append(";status=").append(encode(row.status()));
		return sb.toString();
	}

	private static SessionContract.PerfBenchmarkRecord deserialize(String encoded) {
		Map<String, String> fields = parseFields(encoded);
		return new SessionContract.PerfBenchmarkRecord(
			decode(fields.get("bench_id")),
			decode(fields.get("query_family")),
			decode(fields.get("dataset_profile")),
			parseDouble(fields.get("cold_ms_p50")),
			parseDouble(fields.get("cold_ms_p95")),
			parseDouble(fields.get("warm_ms_p50")),
			parseDouble(fields.get("warm_ms_p95")),
			parseDouble(fields.get("throughput_qps")),
			parseDouble(fields.get("regression_pct")),
			decode(fields.get("status")));
	}

	private static Map<String, String> parseFields(String text) {
		Map<String, String> fields = new HashMap<>();
		if (text == null || text.isBlank()) {
			return fields;
		}
		for (String part : text.split(";")) {
			if (part == null || part.isBlank()) {
				continue;
			}
			int eq = part.indexOf('=');
			if (eq < 0) {
				continue;
			}
			String key = part.substring(0, eq).trim().toLowerCase();
			String value = eq + 1 <= part.length() ? part.substring(eq + 1).trim() : "";
			fields.put(key, value);
		}
		return fields;
	}

	private static String encode(String value) {
		String safe = value != null ? value : "";
		return Base64.getUrlEncoder()
			.withoutPadding()
			.encodeToString(safe.getBytes(StandardCharsets.UTF_8));
	}

	private static String decode(String encoded) {
		if (encoded == null || encoded.isBlank()) {
			return "";
		}
		try {
			return new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
		}
		catch (IllegalArgumentException e) {
			return "";
		}
	}

	private static double parseDouble(String text) {
		if (text == null || text.isBlank()) {
			return 0.0;
		}
		try {
			return Double.parseDouble(text.trim());
		}
		catch (NumberFormatException e) {
			return 0.0;
		}
	}
}
