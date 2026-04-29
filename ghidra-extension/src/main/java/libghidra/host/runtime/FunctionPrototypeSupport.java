package libghidra.host.runtime;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

final class FunctionPrototypeSupport {

	private FunctionPrototypeSupport() {
	}

	// Pulls trailing pointer indirection onto the type token, so
	//   "char *fn(int *p, char **q)"
	// becomes
	//   "char* fn(int* p, char** q)".
	//
	// Ghidra's FunctionSignatureParser accepts the second form but tokenises the
	// first as a name "*fn" (return type "char", name "*fn", which then fails
	// parameter parsing). This is the brittleness reported in the pain-points
	// document Issue 4.
	//
	// The regex matches:
	//   group 1: a trailing identifier or `]` of the type — the rightmost word
	//            of multi-token types like "unsigned long" is captured here;
	//   group 2: one or more `*` separated only by whitespace from group 1
	//            and from group 3;
	//   group 3: an identifier that comes immediately after the `*`s — this is
	//            the variable / function name we want to keep separated.
	//
	// We rewrite to "<group1><group2> <group3>" — pointer fused to the type
	// with a single space before the name. Multiple pointer levels (`**`,
	// `***`) are handled by a possessive count.
	//
	// Conservative scope: only rewrites when the identifier in group 3 is a
	// plain word (no qualifiers between * and the name). We do NOT touch
	// strings inside parens of array sizes (`[N]`) or function-pointer syntax
	// like `int (*fn)(int)` — those use a different shape and the current
	// parser handles them.
	private static final Pattern POINTER_STYLE = Pattern.compile(
			"([A-Za-z_][A-Za-z_0-9]*|\\])(\\s+)(\\*+)\\s*([A-Za-z_][A-Za-z_0-9]*)");

	// Reserved words that are NOT type names — never rewrite when the LHS
	// matches these (otherwise "return *x" or similar fragments would be
	// rewritten). FunctionSignatureParser accepts a small subset of C; these
	// are the only tokens we need to guard against in prototype context.
	private static final java.util.Set<String> NON_TYPE_LHS = java.util.Set.of(
			"return", "if", "else", "while", "for", "do", "switch", "case",
			"break", "continue", "goto", "sizeof", "typedef");

	// --- Pathological-input bail-out (pain-points report Issue 5) -----------
	//
	// FunctionSignatureParser → ghidra.app.util.cparser.C.CParser is not
	// cancellation-aware: once started, it runs to completion holding the
	// program write lock taken at TypesRuntime.setFunctionSignature. A
	// pathological input (very long, very deep nesting, very many `*`) can
	// wedge the parser for the full HTTP read_timeout, blocking every other
	// writer behind the lock.
	//
	// We can't fix CParser from here, so we defend in two layers:
	//   1. Fast heuristic shape-check that rejects obviously-pathological
	//      input before it ever reaches the parser. Cheap, deterministic.
	//   2. Future-with-timeout around parser.parse(...). If parse takes
	//      longer than PARSE_TIMEOUT_MS, throw a structured ParseException
	//      and try to cancel the worker. Cancellation may not actually
	//      release the program lock (CParser doesn't check Thread.interrupt),
	//      but the C++ caller gets a clean error and the worker frees up
	//      from this method's perspective.
	//
	// Both layers are best-effort. The Layer 1 caps below are tuned to be
	// well above any real-world prototype string while still rejecting the
	// classes of input known to wedge CParser.
	private static final int MAX_PROTOTYPE_LENGTH = 4096;
	private static final int MAX_POINTER_LEVELS   = 8;
	private static final int MAX_PAREN_DEPTH      = 8;

	// Default per-parse timeout. Tunable via the JVM system property
	// "libghidra.parse.timeout.ms" — set in dev/test or via -D on the
	// analyzeHeadless command line. Set to 0 (or negative) to disable.
	private static final long DEFAULT_PARSE_TIMEOUT_MS = 15000L;

	private static long parseTimeoutMs() {
		String prop = System.getProperty("libghidra.parse.timeout.ms");
		if (prop == null || prop.isEmpty()) {
			return DEFAULT_PARSE_TIMEOUT_MS;
		}
		try {
			return Long.parseLong(prop);
		}
		catch (NumberFormatException ignored) {
			return DEFAULT_PARSE_TIMEOUT_MS;
		}
	}

	/**
	 * Wraps {@link FunctionSignatureParser#parse(String, String)} in a
	 * {@link Future} with a wall-clock timeout. On timeout we attempt to
	 * cancel/interrupt the worker (best-effort — CParser may not check the
	 * interrupt flag, in which case the worker thread runs to completion in
	 * the background) and throw a structured {@link ParseException} so
	 * callers see a clean error instead of an indefinite hang.
	 */
	private static FunctionDefinitionDataType parseWithTimeout(
			FunctionSignatureParser parser, FunctionSignature existingSignature, String prototype)
			throws ParseException, CancelledException {
		final long timeoutMs = parseTimeoutMs();
		if (timeoutMs <= 0) {
			return parser.parse(existingSignature, prototype);
		}
		ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
			Thread t = new Thread(r, "libghidra-sigparse");
			t.setDaemon(true);
			return t;
		});
		try {
			Future<FunctionDefinitionDataType> future =
				executor.submit((Callable<FunctionDefinitionDataType>) () ->
					parser.parse(existingSignature, prototype));
			try {
				return future.get(timeoutMs, TimeUnit.MILLISECONDS);
			}
			catch (TimeoutException te) {
				future.cancel(true);
				throw new ParseException(
					"FunctionSignatureParser timed out after " + timeoutMs +
					"ms (input may have triggered a CParser pathology); " +
					"raise libghidra.parse.timeout.ms or simplify the prototype");
			}
			catch (InterruptedException ie) {
				future.cancel(true);
				Thread.currentThread().interrupt();
				throw new ParseException("parse interrupted: " + ie.getMessage());
			}
			catch (ExecutionException ee) {
				Throwable cause = ee.getCause();
				if (cause instanceof ParseException pe) {
					throw pe;
				}
				if (cause instanceof CancelledException ce) {
					throw ce;
				}
				if (cause instanceof RuntimeException re) {
					throw re;
				}
				throw new ParseException(
					"parse failed: " + (cause != null ? cause.getMessage() : ee.getMessage()));
			}
		}
		finally {
			executor.shutdownNow();
		}
	}

	/**
	 * Cheap shape-check that rejects pathological prototypes before they
	 * reach Ghidra's CParser. Throws {@link ParseException} on rejection so
	 * the caller surface (typed RPC error code) is identical to a parser
	 * rejection — clients see a structured error instead of a hang.
	 *
	 * Package-private for unit testing.
	 */
	static void validatePrototypeShape(String prototype) throws ParseException {
		if (prototype == null) {
			return;
		}
		if (prototype.length() > MAX_PROTOTYPE_LENGTH) {
			throw new ParseException("prototype too long (" + prototype.length() +
				" chars; max " + MAX_PROTOTYPE_LENGTH + ")");
		}
		int starRun = 0;
		int parenDepth = 0;
		int maxParenDepth = 0;
		for (int i = 0; i < prototype.length(); i++) {
			char ch = prototype.charAt(i);
			if (ch == '*') {
				starRun++;
				if (starRun > MAX_POINTER_LEVELS) {
					throw new ParseException("prototype has too many pointer levels " +
						"(> " + MAX_POINTER_LEVELS + ")");
				}
			}
			else if (!Character.isWhitespace(ch)) {
				starRun = 0;
			}
			if (ch == '(' || ch == '[' || ch == '{') {
				parenDepth++;
				if (parenDepth > maxParenDepth) {
					maxParenDepth = parenDepth;
				}
				if (parenDepth > MAX_PAREN_DEPTH) {
					throw new ParseException("prototype has too many nested parens / brackets " +
						"(> " + MAX_PAREN_DEPTH + ")");
				}
			}
			else if (ch == ')' || ch == ']' || ch == '}') {
				parenDepth--;
			}
		}
	}

	/**
	 * Normalises pointer placement in a C function prototype string so Ghidra's
	 * {@link FunctionSignatureParser} accepts both common spellings
	 * ({@code char *fn(...)} and {@code char* fn(...)}). Idempotent — running
	 * the result through this method again produces the same string.
	 *
	 * Package-private for unit testing.
	 */
	static String normalisePointerStyle(String prototype) {
		if (prototype == null || prototype.isEmpty()) {
			return prototype;
		}
		Matcher m = POINTER_STYLE.matcher(prototype);
		StringBuilder out = new StringBuilder();
		while (m.find()) {
			String lhs = m.group(1);
			String stars = m.group(3);
			String rhs = m.group(4);
			if (NON_TYPE_LHS.contains(lhs)) {
				m.appendReplacement(out, Matcher.quoteReplacement(m.group(0)));
				continue;
			}
			m.appendReplacement(out, Matcher.quoteReplacement(lhs + stars + " " + rhs));
		}
		m.appendTail(out);
		return out.toString();
	}

	static boolean applyFunctionPrototype(Program program, Function function, String prototype)
			throws ParseException, CancelledException, InvalidInputException, DuplicateNameException {
		return applyFunctionPrototype(program, function, prototype, null);
	}

	static boolean applyFunctionPrototype(Program program, Function function, String prototype,
			String callingConvention)
			throws ParseException, CancelledException, InvalidInputException, DuplicateNameException {
		if (program == null || function == null || prototype == null || prototype.isBlank()) {
			throw new InvalidInputException("prototype is empty");
		}

		// Layer 1 of Issue 5 Layer-2 defence: cheap shape-check rejects
		// pathological inputs (overlong, too-deep nesting, too-many-stars)
		// before they reach CParser, which is not cancellation-aware.
		validatePrototypeShape(prototype);

		FunctionSignatureParser parser = new FunctionSignatureParser(program.getDataTypeManager(), null);

		// Pre-normalise pointer style so "char *fn(...)" parses the same as
		// "char* fn(...)". On any unexpected failure of the normalised form,
		// fall back to the original string so we never make things worse.
		String normalised = normalisePointerStyle(prototype);
		final FunctionSignature existing = function.getSignature(true);
		FunctionDefinitionDataType parsed;
		try {
			parsed = parseWithTimeout(parser, existing, normalised);
		}
		catch (ParseException e) {
			if (normalised.equals(prototype)) {
				throw e;
			}
			parsed = parseWithTimeout(parser, existing, prototype);
		}
		if ((parsed == null || parsed.getReturnType() == null) && !normalised.equals(prototype)) {
			parsed = parseWithTimeout(parser, existing, prototype);
		}
		if (parsed == null || parsed.getReturnType() == null) {
			throw new InvalidInputException("prototype parse failed");
		}

		DataTypeManager manager = program.getDataTypeManager();
		ReturnParameterImpl returnParameter =
			new ReturnParameterImpl(parsed.getReturnType().clone(manager), program);

		// Use explicit calling convention if provided, otherwise from parser.
		String convention = callingConvention;
		if (convention == null || convention.isBlank()) {
			convention = parsed.getCallingConventionName();
			if (convention != null && convention.isBlank()) {
				convention = null;
			}
		}

		boolean isThiscall = "__thiscall".equals(convention);
		ParameterDefinition[] args = parsed.getArguments();

		// For __thiscall: the first parameter in the prototype IS the this type.
		// Extract it so updateFunction doesn't create a duplicate void* this.
		DataType thisType = null;
		String thisName = null;
		int startIndex = 0;
		if (isThiscall && args.length > 0 && args[0] != null &&
			args[0].getDataType() instanceof Pointer) {
			thisType = args[0].getDataType().clone(manager);
			thisName = args[0].getName();
			startIndex = 1;
		}

		List<Parameter> parameters = new ArrayList<>();
		for (int i = startIndex; i < args.length; i++) {
			ParameterDefinition arg = args[i];
			if (arg == null || arg.getDataType() == null) {
				throw new InvalidInputException("parameter " + i + " has no data type");
			}
			String paramName = arg.getName();
			if (paramName == null || paramName.isBlank()) {
				paramName = "arg" + (i - startIndex);
			}
			ParameterImpl parameter = new ParameterImpl(
				paramName,
				arg.getDataType().clone(manager),
				program,
				SourceType.USER_DEFINED);
			parameter.setComment(arg.getComment());
			parameters.add(parameter);
		}

		function.updateFunction(
			convention,
			returnParameter,
			parameters,
			FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
			false,
			SourceType.USER_DEFINED);
		function.setVarArgs(parsed.hasVarArgs());

		// Apply the this type after updateFunction created the auto parameter.
		if (thisType != null) {
			Parameter autoThis = function.getParameter(0);
			if (autoThis != null && autoThis.isAutoParameter()) {
				function.setCustomVariableStorage(true);
				autoThis.setDataType(thisType, SourceType.USER_DEFINED);
				if (thisName != null && !thisName.isBlank()) {
					autoThis.setName(thisName, SourceType.USER_DEFINED);
				}
			}
		}

		String parsedName = parsed.getName();
		if (parsedName != null && !parsedName.isBlank() && !parsedName.equals(function.getName())) {
			function.setName(parsedName, SourceType.USER_DEFINED);
		}
		return true;
	}
}
