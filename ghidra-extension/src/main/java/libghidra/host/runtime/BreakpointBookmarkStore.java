package libghidra.host.runtime;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;

final class BreakpointBookmarkStore {

	static final String BOOKMARK_TYPE = "GhidraAPI Breakpoint";
	private static final String DEFAULT_CATEGORY = "libghidra.breakpoint";

	static final class BreakpointRecord {
		long address;
		boolean enabled = true;
		String kind = "software";
		long size = 1;
		String condition = "";
		String group = "";
	}

	private BreakpointBookmarkStore() {
	}

	static List<Bookmark> all(BookmarkManager manager) {
		List<Bookmark> out = new ArrayList<>();
		if (manager == null) {
			return out;
		}
		Iterator<Bookmark> it = manager.getBookmarksIterator(BOOKMARK_TYPE);
		while (it.hasNext()) {
			Bookmark bookmark = it.next();
			if (bookmark != null) {
				out.add(bookmark);
			}
		}
		return out;
	}

	static Bookmark findAt(BookmarkManager manager, Address address) {
		if (manager == null || address == null) {
			return null;
		}
		Bookmark[] marks = manager.getBookmarks(address, BOOKMARK_TYPE);
		if (marks == null || marks.length == 0) {
			return null;
		}
		for (Bookmark bookmark : marks) {
			if (bookmark != null) {
				return bookmark;
			}
		}
		return null;
	}

	static boolean removeAt(BookmarkManager manager, Address address) {
		if (manager == null || address == null) {
			return false;
		}
		Bookmark[] marks = manager.getBookmarks(address, BOOKMARK_TYPE);
		if (marks == null || marks.length == 0) {
			return false;
		}
		boolean removed = false;
		for (Bookmark bookmark : marks) {
			if (bookmark != null) {
				manager.removeBookmark(bookmark);
				removed = true;
			}
		}
		return removed;
	}

	static void upsert(BookmarkManager manager, Address address, BreakpointRecord row) {
		if (manager == null || address == null || row == null) {
			return;
		}
		removeAt(manager, address);
		manager.setBookmark(address, BOOKMARK_TYPE, bookmarkCategory(row.group), serialize(row));
	}

	static BreakpointRecord fromBookmark(Bookmark bookmark) {
		BreakpointRecord row = new BreakpointRecord();
		if (bookmark == null) {
			return row;
		}
		row.address = bookmark.getAddress().getOffset();
		row.group = groupFromCategory(bookmark.getCategory());
		Map<String, String> fields = parseFields(bookmark.getComment());
		row.enabled = parseLong(fields.get("enabled"), 1) != 0;
		row.kind = decodeString(fields, "kind_b64", "kind", "software");
		row.size = Math.max(1L, parseLong(fields.get("size"), 1));
		row.condition = decodeString(fields, "condition_b64", "condition", "");
		return row;
	}

	private static String serialize(BreakpointRecord row) {
		String kind = row.kind != null && !row.kind.isBlank() ? row.kind.trim() : "software";
		String condition = row.condition != null ? row.condition : "";
		String kind64 = Base64.getUrlEncoder()
				.withoutPadding()
				.encodeToString(kind.getBytes(StandardCharsets.UTF_8));
		String condition64 = Base64.getUrlEncoder()
				.withoutPadding()
				.encodeToString(condition.getBytes(StandardCharsets.UTF_8));
		return "enabled=" + (row.enabled ? 1 : 0)
			+ ";kind_b64=" + kind64
			+ ";size=" + Math.max(1L, row.size)
			+ ";condition_b64=" + condition64;
	}

	private static Map<String, String> parseFields(String text) {
		Map<String, String> fields = new HashMap<>();
		if (text == null || text.isBlank()) {
			return fields;
		}
		String[] parts = text.split(";");
		for (String part : parts) {
			if (part == null || part.isBlank()) {
				continue;
			}
			int eq = part.indexOf('=');
			if (eq <= 0 || eq + 1 >= part.length()) {
				continue;
			}
			String key = part.substring(0, eq).trim().toLowerCase();
			String value = part.substring(eq + 1).trim();
			fields.put(key, value);
		}
		return fields;
	}

	private static String decodeString(
			Map<String, String> fields,
			String b64Key,
			String plainKey,
			String fallback) {
		if (fields == null) {
			return fallback;
		}
		String encoded = fields.get(b64Key);
		if (encoded != null && !encoded.isBlank()) {
			try {
				return new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
			}
			catch (IllegalArgumentException e) {
				return fallback;
			}
		}
		String plain = fields.get(plainKey);
		if (plain == null || plain.isBlank()) {
			return fallback;
		}
		return plain;
	}

	private static long parseLong(String text, long fallback) {
		if (text == null || text.isBlank()) {
			return fallback;
		}
		try {
			return Long.parseLong(text.trim());
		}
		catch (NumberFormatException e) {
			return fallback;
		}
	}

	private static String bookmarkCategory(String group) {
		if (group == null || group.isBlank()) {
			return DEFAULT_CATEGORY;
		}
		return group.trim();
	}

	private static String groupFromCategory(String category) {
		if (category == null || category.isBlank()) {
			return "";
		}
		String trimmed = category.trim();
		if (DEFAULT_CATEGORY.equalsIgnoreCase(trimmed)) {
			return "";
		}
		return trimmed;
	}
}
