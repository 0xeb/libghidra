package libghidra.host.runtime;

public final class SessionRpcException extends RuntimeException {

	private final String code;

	public SessionRpcException(String code, String message) {
		super(message);
		this.code = code != null ? code : "internal_error";
	}

	public String code() {
		return code;
	}
}
