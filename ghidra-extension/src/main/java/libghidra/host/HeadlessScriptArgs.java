package libghidra.host;

import java.util.HashMap;
import java.util.Map;

public final class HeadlessScriptArgs {

	private HeadlessScriptArgs() {
	}

	public static Map<String, String> parse(String[] scriptArgs) {
		Map<String, String> out = new HashMap<>();
		if (scriptArgs == null) {
			return out;
		}
		for (int i = 0; i < scriptArgs.length; i++) {
			String token = scriptArgs[i];
			if (token == null || token.isBlank()) {
				continue;
			}
			String trimmed = token.trim();
			if (trimmed.startsWith("--")) {
				String option = trimmed.substring(2).trim();
				if (option.isEmpty()) {
					continue;
				}
				int eq = option.indexOf('=');
				if (eq > 0) {
					String key = option.substring(0, eq).trim().toLowerCase();
					String value = option.substring(eq + 1);
					if (!key.isEmpty()) {
						out.put(key, value);
					}
					continue;
				}
				String key = option.toLowerCase();
				if (i + 1 < scriptArgs.length) {
					out.put(key, scriptArgs[++i]);
				}
				continue;
			}
			if (i + 1 < scriptArgs.length) {
				String next = scriptArgs[i + 1];
				if (next != null) {
					String nextTrimmed = next.trim();
					if (!nextTrimmed.isEmpty() && !nextTrimmed.startsWith("--") &&
						nextTrimmed.indexOf('=') < 0) {
						out.put(trimmed.toLowerCase(), next);
						i++;
						continue;
					}
				}
			}
			int eq = trimmed.indexOf('=');
			if (eq <= 0) {
				continue;
			}
			String key = trimmed.substring(0, eq).trim().toLowerCase();
			String value = trimmed.substring(eq + 1);
			if (!key.isEmpty()) {
				out.put(key, value);
			}
		}
		return out;
	}

	public static String valueOrDefault(String value, String fallback) {
		if (value == null || value.isBlank()) {
			return fallback;
		}
		return value;
	}

	public static int parseInt(String value, int fallback) {
		if (value == null || value.isBlank()) {
			return fallback;
		}
		try {
			return Integer.parseInt(value.trim());
		}
		catch (NumberFormatException e) {
			return fallback;
		}
	}

	public static long parseLong(String value, long fallback) {
		if (value == null || value.isBlank()) {
			return fallback;
		}
		try {
			return Long.parseLong(value.trim());
		}
		catch (NumberFormatException e) {
			return fallback;
		}
	}
}
