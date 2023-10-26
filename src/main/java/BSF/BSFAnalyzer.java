package BSF;

import ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater;
import ghidra.app.plugin.core.string.StringAndScores;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BSFAnalyzer extends AbstractAnalyzer {
    private static final String NAME = "Better String Finder";
    private static final String DESCRIPTION = "This analyzer searches for strings with non-ASCII encodings using International Components of Unicode (ICU)'s library.";

    private CodeUnitIterator instructionIterator;
    private CodeUnitIterator definedDataIterator;
    private CodeUnit currInstrCU, currDataCU;
    private Address instrStart, instrEnd, dataStart, dataEnd;

    private int endAlignment = 4;
    private boolean requireNullEnd = true;

    // ADD PARAMETER FOR DEFAULT ENCODING OR TO FIGURE IT OUT

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
        // Why not do both????
        Memory memory = program.getMemory();

        // Get Ascii Value
        StringAndScores candidate =
                new StringAndScores(foundString.getString(memory), false);

        int scoredLength = 0; candidate.getScoredStringLength();
        if (scoredLength < 3) { // ABSOLUTE_MIN_STR_LENGTH
            //String is non ascii so find the other encoding
            // else, just return since it is found in the normal string finder

            // Get special encoding most likely value
            MemBuffer membuf = new DumbMemBufferImpl(memory, foundString.getAddress());
            byte b[] = new byte[foundString.getLength()];
            int bytesRead = membuf.getBytes(b, 0);
            BSFStringAndScores bsfCandidate = new BSFStringAndScores(b);
            this.bsfScorer.scoreBSFString(bsfCandidate);

            Address start = foundString.getAddress();
            Address end = foundString.getEndAddress();

            DataType dataType = foundString.getDataType();
            Listing listing = program.getListing();
            if (!DataUtilities.isUndefinedRange(program, start, end)) {
                if (true) { //allowStringCreationWithExistringSubstring
                    // Check for single string with a common end address which be consumed
                    Data definedData = listing.getDefinedDataContaining(end);
                    if (definedData == null || definedData.getAddress().compareTo(start) <= 0 ||
                            !dataType.isEquivalent(definedData.getDataType()) ||
                            !DataUtilities.isUndefinedRange(program, start,
                                    definedData.getAddress().previous())) {
                        return; // conflict data can not be consumed
                    }
                }
                else {
                    return; // data conflict
                }
            }

//            boolean hasOffcutReferences = false;
//            if (!allowStringCreationWithOffcutReferences) {
//                hasOffcutReferences = hasOffcut(start, end, program);
//            }
//            // Only make a string if no offcut references or there are offcut references,
//            // but user says so
//            if (hasOffcutReferences && !allowStringCreationWithOffcutReferences) {
//                return;
//            }
//

            try {

                int length = foundString.getLength();

                if (requireNullEnd && endAlignment > 1) {
                    int padLength = getStringPadLength(program, end);

                    // Check to make sure extra padding doesn't go over memory
                    // boundaries or allow writing over defined data/instructions
                    if (padLength > 0) {
                        length += getValidPadLength(program, end, padLength);
                    }
                }

                // Get old string details to change encoding

                // Need to pass length into command for when (requireNullEnd == false).
                // Using the CreateDataCmd (which doesn't allow you to pass in a length)
                // creates a string at the starting address up to the length of the next
                // "00".
                DataUtilities.createData(program, start, foundString.getDataType(), length,
                        DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

                Data recentDefinedString = listing.getDefinedDataContaining(end);
                recentDefinedString.setValue("charset", bsfCandidate.getBestMatchingEncoding());

                Msg.trace(this, "Created string '" + bsfCandidate.getEncodedString() + "' at " + start);

                monitor.setMessage("Creating String at " + start);
            }
            catch (Exception e) {
                throw new AssertException("Unexpected exception", e);
            }

        }
    }

    private int getStringPadLength(Program program, Address endAddress) {

        Address nextAddr = endAddress.next();
        if (nextAddr == null) {
            return 0;
        }

        long modResult = nextAddr.getOffset() % endAlignment;
        if (modResult == 0) {
            return 0;
        }

        int padBytesNeeded = endAlignment - (int) modResult;
        try {
            byte[] bytes = new byte[padBytesNeeded];
            if (program.getMemory().getBytes(nextAddr, bytes) == padBytesNeeded) {

                for (byte b : bytes) {
                    if (b != 0) {
                        return 0;
                    }
                }
            }
        }
        catch (Exception e) {
            return 0;
        }

        return padBytesNeeded;
    }

    /**
     * Verify that adding padding bytes won't violate boundaries or allow defined data
     * or instructions to be overwritten.
     *
     * @param program		current program
     * @param stringEndAddress	strings' end address
     * @param padLength		number of pad bytes
     * @return	actual number of pad bytes to add to the string
     */
    private int getValidPadLength(Program program, Address stringEndAddress, int padLength) {

        Listing listing = program.getListing();
        Address address = stringEndAddress;

        for (int i = 0; i < padLength; i++) {
            address = address.next();
            if (address == null) {
                return 0;
            }
            CodeUnit cu = listing.getCodeUnitContaining(address);
            if (cu == null) {
                return 0; // null implies there cannot be data here
            }

            if (!(cu instanceof Data) || ((Data) cu).isDefined()) {
                return 0;
            }
        }

        return padLength;
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
