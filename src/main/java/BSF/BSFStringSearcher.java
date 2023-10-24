package BSF;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.util.string.AbstractStringSearcher;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.util.ascii.CharSetRecognizer;
import ghidra.util.ascii.Sequence;

public class BSFStringSearcher extends AbstractStringSearcher {

    private boolean requireNullTermination;

    protected BSFStringSearcher(Program program, int minimumStringSize, int alignment, boolean requireNullTermination) {
        super(program, new BSFCharSetRecognizer(), minimumStringSize, alignment, true, false, false);
        this.requireNullTermination = requireNullTermination;
    }

    @Override
    protected void processSequence(FoundStringCallback callback, Sequence sequence, MemBuffer buf) {
        if (this.requireNullTermination && !sequence.isNullTerminated()) {
            return;
        }
        callback.stringFound(getFoundString(buf, sequence, sequence.getStringDataType()));
    }
}
