/**
 * Runtime package layout after the host split:
 *
 * <p>{@link libghidra.host.runtime.RuntimeBundle} is the composition root. It wires one
 * shared {@link libghidra.host.runtime.HostState} into narrow domain runtimes:
 * {@link libghidra.host.runtime.HealthRuntime},
 * {@link libghidra.host.runtime.SessionRuntime},
 * {@link libghidra.host.runtime.MemoryRuntime},
 * {@link libghidra.host.runtime.FunctionsRuntime},
 * {@link libghidra.host.runtime.SymbolsRuntime},
 * {@link libghidra.host.runtime.XrefsRuntime},
 * {@link libghidra.host.runtime.TypesRuntime},
 * {@link libghidra.host.runtime.DecompilerRuntime}, and
 * {@link libghidra.host.runtime.ListingRuntime}.
 *
 * <p>Each service handler depends on the corresponding {@code *Operations} interface instead of a
 * single wide runtime surface. Shared mechanics such as locking, DTO mapping, type parsing, and
 * decompiler helpers stay in small support files so the domain runtimes can stay focused on one
 * responsibility.
 */
package libghidra.host.runtime;
