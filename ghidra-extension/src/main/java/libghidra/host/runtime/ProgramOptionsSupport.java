// Copyright (c) 2024-2026 Elias Bachaalany
// SPDX-License-Identifier: LicenseRef-Human-Origin-Source-1.0
//
// This file is licensed under the Human-Origin Source License v1.0.
// See LICENSE.

package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import libghidra.host.contract.SessionContract;

/**
 * Program options (every {@link Program#getOptionsNames()} category) and the auto-analysis
 * helpers shared by import, open-with-analyze and background analysis jobs.
 *
 * <p>Measured: a program's analyzer options only exist
 * once its {@link AutoAnalysisManager} has been created (a cold program exposes 1 option,
 * 127 after), and creating the manager needs no transaction and leaves the modification
 * number untouched. Listing is therefore a pure read.
 */
final class ProgramOptionsSupport {

	/** The only category whose options are writable through the API. */
	static final String ANALYZERS_CATEGORY = Program.ANALYSIS_PROPERTIES;

	private ProgramOptionsSupport() {
	}

	static List<SessionContract.ProgramOptionRecord> list(
			Program program, String category, String nameFilter) {
		// Registers the analyzer options on a program no manager has touched yet.
		AutoAnalysisManager.getAnalysisManager(program);
		String wantedCategory = category != null ? category.trim() : "";
		String filter = nameFilter != null ? nameFilter.trim().toLowerCase(Locale.ROOT) : "";
		List<SessionContract.ProgramOptionRecord> out = new ArrayList<>();
		for (String categoryName : program.getOptionsNames()) {
			if (!wantedCategory.isEmpty() && !wantedCategory.equals(categoryName)) {
				continue;
			}
			Options options = program.getOptions(categoryName);
			List<String> names = new ArrayList<>(options.getOptionNames());
			names.sort(String::compareTo);
			for (String name : names) {
				if (!filter.isEmpty() && !name.toLowerCase(Locale.ROOT).contains(filter)) {
					continue;
				}
				out.add(toRecord(categoryName, options, name));
			}
		}
		return out;
	}

	/** Apply one typed write; returns the previous value. Caller holds the write lock. */
	static String set(Program program, String category, String name, String value) {
		if (name == null || name.isBlank()) {
			throw new SessionRpcException("invalid_argument", "option name is required");
		}
		String categoryName = category != null ? category.trim() : "";
		if (!ANALYZERS_CATEGORY.equals(categoryName)) {
			throw new SessionRpcException("invalid_argument",
				"only \"" + ANALYZERS_CATEGORY + "\" options are settable, not \"" + categoryName + "\"");
		}
		AutoAnalysisManager.getAnalysisManager(program);
		Options options = program.getOptions(categoryName);
		if (!options.contains(name)) {
			throw new SessionRpcException("invalid_argument", "no such option: " + name);
		}
		OptionType type = options.getType(name);
		if (!isSettableType(type)) {
			throw new SessionRpcException("invalid_argument",
				"option " + name + " has type " + typeName(type) + ", which is not settable");
		}
		String previous = valueText(options, name);
		String text = value != null ? value : "";
		int tx = program.startTransaction("libghidra set option " + name);
		boolean commit = false;
		try {
			applyTyped(options, name, type, text);
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
		return previous;
	}

	/**
	 * Apply import-time analyzer patterns to one loaded program; "on" patterns run after
	 * "off". Records the matched toggle names per pattern into {@code matches} (keyed by
	 * list position, created on first use).
	 */
	static void applyAnalyzerPatterns(Program program, List<String> off, List<String> on,
			List<SessionContract.AnalyzerPatternMatch> matches) {
		List<String> offPatterns = off != null ? off : List.of();
		List<String> onPatterns = on != null ? on : List.of();
		if (offPatterns.isEmpty() && onPatterns.isEmpty()) {
			return;
		}
		AutoAnalysisManager.getAnalysisManager(program);
		Options options = program.getOptions(ANALYZERS_CATEGORY);
		List<String> toggles = new ArrayList<>();
		for (String name : options.getOptionNames()) {
			if (options.getType(name) == OptionType.BOOLEAN_TYPE && !name.contains(".")) {
				toggles.add(name);
			}
		}
		toggles.sort(String::compareTo);
		int tx = program.startTransaction("libghidra analyzer overrides");
		boolean commit = false;
		try {
			int index = 0;
			for (String pattern : offPatterns) {
				applyPattern(options, toggles, pattern, false, index++, matches);
			}
			for (String pattern : onPatterns) {
				applyPattern(options, toggles, pattern, true, index++, matches);
			}
			commit = true;
		}
		finally {
			program.endTransaction(tx, commit);
		}
	}

	private static void applyPattern(Options options, List<String> toggles, String pattern,
			boolean enabled, int index, List<SessionContract.AnalyzerPatternMatch> matches) {
		String trimmed = pattern != null ? pattern.trim() : "";
		while (matches.size() <= index) {
			matches.add(null);
		}
		SessionContract.AnalyzerPatternMatch existing = matches.get(index);
		Set<String> hits = new LinkedHashSet<>(existing != null ? existing.options() : List.of());
		if (!trimmed.isEmpty()) {
			for (String name : toggles) {
				if (patternMatches(name, trimmed)) {
					options.setBoolean(name, enabled);
					hits.add(name);
				}
			}
		}
		matches.set(index, new SessionContract.AnalyzerPatternMatch(
			trimmed, enabled, new ArrayList<>(hits)));
	}

	/** '*' makes the pattern a whole-name glob; otherwise a substring. Case-insensitive. */
	static boolean patternMatches(String name, String pattern) {
		if (pattern.indexOf('*') < 0) {
			return name.toLowerCase(Locale.ROOT).contains(pattern.toLowerCase(Locale.ROOT));
		}
		String[] parts = pattern.split("\\*", -1);
		StringBuilder regex = new StringBuilder();
		for (int i = 0; i < parts.length; i++) {
			if (i > 0) {
				regex.append(".*");
			}
			regex.append(Pattern.quote(parts[i]));
		}
		return Pattern.compile(regex.toString(), Pattern.CASE_INSENSITIVE | Pattern.DOTALL)
			.matcher(name)
			.matches();
	}

	/**
	 * Run auto-analysis. {@code all} re-runs every enabled analyzer over the whole program;
	 * otherwise only the work the manager has queued for edits since the program was bound
	 * runs (a reopened program starts with an empty queue, so that is normally nothing).
	 * "Changed" never escalates to a full pass on its own: programs imported before the
	 * analyzed flag was recorded would otherwise be silently re-analyzed on every reopen.
	 * Headless (no PluginTool) {@code startAnalysis} runs inline and blocks until done or
	 * cancelled. Caller owns the transaction.
	 */
	static void analyze(Program program, boolean all, TaskMonitor monitor) {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
		manager.initializeOptions();
		if (all) {
			manager.reAnalyzeAll(null);
		}
		manager.startAnalysis(monitor);
		if (monitor.isCancelled()) {
			throw new SessionRpcException("cancelled", "analysis was cancelled");
		}
		if (all) {
			GhidraProgramUtilities.markProgramAnalyzed(program);
		}
	}

	private static SessionContract.ProgramOptionRecord toRecord(
			String category, Options options, String name) {
		OptionType type = options.getType(name);
		List<String> allowed = List.of();
		Object current = safeObject(options, name);
		if (current instanceof Enum<?> constant) {
			allowed = Arrays.stream(constant.getDeclaringClass().getEnumConstants())
				.map(Enum::name)
				.toList();
		}
		String description;
		try {
			description = options.getDescription(name);
		}
		catch (RuntimeException e) {
			description = "";
		}
		Object defaultValue;
		try {
			defaultValue = options.getDefaultValue(name);
		}
		catch (RuntimeException e) {
			defaultValue = null;
		}
		return new SessionContract.ProgramOptionRecord(
			category,
			name,
			asText(current),
			typeName(type),
			description != null ? description : "",
			asText(defaultValue),
			ANALYZERS_CATEGORY.equals(category) && isSettableType(type),
			allowed);
	}

	private static void applyTyped(Options options, String name, OptionType type, String value) {
		switch (type) {
			case BOOLEAN_TYPE -> options.setBoolean(name, parseBoolean(name, value));
			case INT_TYPE -> {
				long parsed = parseLong(name, value);
				if (parsed < Integer.MIN_VALUE || parsed > Integer.MAX_VALUE) {
					throw new SessionRpcException("invalid_argument",
						"value out of int range for " + name + ": " + value);
				}
				options.setInt(name, (int) parsed);
			}
			case LONG_TYPE -> options.setLong(name, parseLong(name, value));
			case DOUBLE_TYPE -> options.setDouble(name, parseDouble(name, value));
			case FLOAT_TYPE -> options.setFloat(name, (float) parseDouble(name, value));
			case STRING_TYPE -> options.setString(name, value);
			case ENUM_TYPE -> setEnum(options, name, value);
			default -> throw new SessionRpcException("invalid_argument",
				"option " + name + " has type " + typeName(type) + ", which is not settable");
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private static void setEnum(Options options, String name, String value) {
		Object current = safeObject(options, name);
		if (!(current instanceof Enum<?> constant)) {
			throw new SessionRpcException("invalid_argument",
				"option " + name + " has no enum value to resolve against");
		}
		Enum<?>[] constants = constant.getDeclaringClass().getEnumConstants();
		String wanted = value.trim();
		Enum match = null;
		for (Enum<?> candidate : constants) {
			if (candidate.name().equals(wanted)) {
				match = candidate;
				break;
			}
		}
		if (match == null) {
			for (Enum<?> candidate : constants) {
				if (candidate.name().equalsIgnoreCase(wanted) ||
					candidate.toString().equalsIgnoreCase(wanted)) {
					match = candidate;
					break;
				}
			}
		}
		if (match == null) {
			throw new SessionRpcException("invalid_argument",
				"not one of " + Arrays.stream(constants).map(Enum::name).toList() + " for " + name +
					": " + value);
		}
		options.setEnum(name, match);
	}

	private static boolean isSettableType(OptionType type) {
		if (type == null) {
			return false;
		}
		return switch (type) {
			case BOOLEAN_TYPE, INT_TYPE, LONG_TYPE, DOUBLE_TYPE, FLOAT_TYPE, STRING_TYPE, ENUM_TYPE -> true;
			default -> false;
		};
	}

	static String typeName(OptionType type) {
		if (type == null) {
			return "";
		}
		String name = type.name().toLowerCase(Locale.ROOT);
		return name.endsWith("_type") ? name.substring(0, name.length() - "_type".length()) : name;
	}

	private static String valueText(Options options, String name) {
		return asText(safeObject(options, name));
	}

	private static Object safeObject(Options options, String name) {
		try {
			return options.getObject(name, null);
		}
		catch (RuntimeException e) {
			return null;
		}
	}

	private static String asText(Object value) {
		if (value == null) {
			return "";
		}
		if (value instanceof Enum<?> constant) {
			return constant.name();
		}
		return String.valueOf(value);
	}

	private static boolean parseBoolean(String name, String value) {
		String v = value.trim().toLowerCase(Locale.ROOT);
		switch (v) {
			case "true", "1", "yes", "on":
				return true;
			case "false", "0", "no", "off":
				return false;
			default:
				throw new SessionRpcException("invalid_argument",
					"not a boolean for " + name + ": " + value);
		}
	}

	private static long parseLong(String name, String value) {
		try {
			return Long.parseLong(value.trim());
		}
		catch (NumberFormatException e) {
			throw new SessionRpcException("invalid_argument",
				"not an integer for " + name + ": " + value);
		}
	}

	private static double parseDouble(String name, String value) {
		try {
			return Double.parseDouble(value.trim());
		}
		catch (NumberFormatException e) {
			throw new SessionRpcException("invalid_argument",
				"not a number for " + name + ": " + value);
		}
	}
}
