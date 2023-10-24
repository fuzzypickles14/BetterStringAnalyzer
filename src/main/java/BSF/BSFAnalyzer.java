package BSF;

import ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater;
import ghidra.app.plugin.core.string.StringAndScores;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BSFAnalyzer extends AbstractAnalyzer {
    private static final String NAME = "Better String Finder";
    private static final String DESCRIPTION = "This analyzer searches for strings with non-ASCII encodings using International Components of Unicode (ICU)'s library.";

    private CodeUnitIterator instructionIterator;
    private CodeUnitIterator definedDataIterator;
    private CodeUnit currInstrCU, currDataCU;
    private Address instrStart, instrEnd, dataStart, dataEnd;

    private BSFStringScorer bsfScorer;

    public BSFAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after().after());
        this.bsfScorer = new BSFStringScorer();
    }

    @Override
    public boolean canAnalyze(Program program) {
        // As long as it has memory blocks defined, we can analyze
        return program.getMinAddress() != null;
    }

    private AddressSet getMemoryBlockAddresses(MemoryBlock[] blocks) {

        AddressSet addresses = new AddressSet();
        for (MemoryBlock memBlock : blocks) {
            if (memBlock.getPermissions() > 0) {
                addresses = addresses.union(new AddressSet(memBlock.getStart(), memBlock.getEnd()));
            }
        }
        return addresses;
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, ghidra.app.util.importer.MessageLog log) throws CancelledException {
        AddressFactory factory = program.getAddressFactory();
        AddressSpace[] addressSpaces = factory.getAddressSpaces();

        AddressSetView initializedMemory = program.getMemory().getLoadedAndInitializedAddressSet();
        try {
            if (set == null) {
                set = new AddressSet(initializedMemory);
            }

            AddressSet searchSet = initializedMemory.intersect(set);

            // searchOnlyAccessibleMemBlocks
            if (true) {

                // Intersect current AddressSet with accessible memory blocks
                MemoryBlock[] blocks = program.getMemory().getBlocks();
                AddressSet memoryBlockAddresses = getMemoryBlockAddresses(blocks);
                searchSet = searchSet.intersect(memoryBlockAddresses);
            }

            for (AddressSpace space : addressSpaces) {

                monitor.checkCancelled();

                // Portion of current address space that intersects with initialized memory
                AddressSet intersecting =
                        searchSet.intersectRange(space.getMinAddress(), space.getMaxAddress());

                // Initialize, because we don't want to use the same iterators or
                // code units when we change address spaces
                instructionIterator = null;
                definedDataIterator = null;
                currInstrCU = null;
                currDataCU = null;

                findStrings(program, intersecting, monitor);
            }


        } catch (CancelledException e) {
            throw e;
        }
        return true;
    }
    private void createStringIfValid(FoundString foundString, Program program,
                                     AddressSetView addressSet, TaskMonitor monitor)
    {
        if (monitor.isCancelled()) {
            return;
        }

        // Get raw bytes from program instead of string
        // Need to check for non ascii characters in string and then pick right decoder
        Memory memory = program.getMemory();
        MemBuffer membuf = new DumbMemBufferImpl(memory, foundString.getAddress());
        byte b[] = new byte[foundString.getLength()];
        int bytesRead = membuf.getBytes(b, 0);
        System.out.println(b);
        this.bsfScorer.scoreBSFString(b);

        BSFStringAndScores candidate = new BSFStringAndScores(foundString.getString(memory));

        int scoredLength = candidate.getScoredStringLength();
        if (scoredLength < 3) {  //TODO ABSOLUTE_MIN_STR_LENGTH
            return;
        }
        this.bsfScorer.scoreBSFString(candidate);

    }
    /**
     * Determines if found ASCII strings are valid strings, and creates them if so.
     *
     * @param program   program in which to search for strings
     * @param addressSet  the address set to search
     * @param monitor  monitor for this process
     */
    private void findStrings(final Program program, AddressSetView addressSet, TaskMonitor monitor) {

        FoundStringCallback foundStringCallback =
                foundString -> createStringIfValid(foundString, program, addressSet, monitor);

        BSFStringSearcher searcher = new BSFStringSearcher(program, 3, 1, true); //program, minimumStringLength, alignVal

        searcher.search(addressSet, foundStringCallback, true, monitor);
    }

    @Override
    public AnalysisOptionsUpdater getOptionsUpdater() {
        return super.getOptionsUpdater();
    }

}
