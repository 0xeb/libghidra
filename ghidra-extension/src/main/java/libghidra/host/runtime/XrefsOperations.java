package libghidra.host.runtime;

import libghidra.host.contract.XrefsContract;

public interface XrefsOperations {

	XrefsContract.ListXrefsResponse listXrefs(XrefsContract.ListXrefsRequest request);
}
