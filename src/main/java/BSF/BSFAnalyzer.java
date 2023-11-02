package BSF;

import ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater;
import ghidra.app.plugin.core.string.NGramUtils;
import ghidra.app.plugin.core.string.StringAndScores;
import ghidra.app.plugin.core.string.StringsAnalyzer;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.framework.options.Options;

public class BSFAnalyzer extends AbstractAnalyzer {
    private static final String NAME = "Better String Finder";
    private static final String DESCRIPTION = "This analyzer searches for strings with non-ASCII encodings using International Components of Unicode (ICU)'s library.";

    private static final String ENCODING_OPTION_NAME = "String Encoding";

    private static final String ENCODING_OPTION_DESCRIPTION = "The encoding to give all strings found with this analyzer";

    private static final String MINIMUM_STRING_LENGTH_OPTION_NAME = "Minimum String Length";
    private static final String MINIMUM_STRING_LENGTH_OPTION_DESCRIPTION =
            "The smallest number of characters in a string to be considered a valid string. " +
                    "(Smaller numbers will give more false positives). String length must be 4 " +
                    "or greater.";

    private static final String REQUIRE_NULL_TERMINATION_OPTION_NAME =
            "Require Null Termination for String";
    private static final String REQUIRE_NULL_TERMINATION_OPTION_DESCRIPTION =
            "If set to true, requires all strings to end in null.";

    private static final String ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME =
            "Create Strings Containing References";
    private static final String ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DESCRIPTION =
            "If checked, allows a string that contains, but does not start with, one or more references" +
                    " to be created.";

    private static final String ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME =
            "Create Strings Containing Existing Strings";
    private static final String ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DESCRIPTION =
            "If checked, allows a string to be created even if it contains existing strings (existing " +
                    "strings will be cleared). The string will be created only if existing strings (a) " +
                    "are wholly contained within the potential string, (b) do not share the same starting " +
                    "address as the potential string, (c) share the same ending address as the potential " +
                    "string, and (d) are the same datatype as the potential string.";

    private static final String START_ALIGNMENT_OPTION_NAME = "String Start Alignment";
    private static final String START_ALIGNMENT_OPTION_DESCRIPTION =
            "Specifies an alignment requirement for the start of the string. An alignment of 1 " +
                    "means the string can start at any address.  An alignment of 2 means the string " +
                    "must start on an even address and so on.  Only allowed values are 1,2, and 4.";

    private static final String END_ALIGNMENT_OPTION_NAME = "String end alignment";
    private static final String END_ALIGNMENT_OPTION_DESCRIPTION =
            "Specifies an alignment requirement for the end of the string. An alignment of 1 " +
                    "means the string can end at any address. Alignments greater than 1 require that " +
                    "(a) the 'require null termination' option be enabled, and (b) if the null-terminated " +
                    "string does not end at an aligned boundary, that there exist enough trailing '0' " +
                    "bytes following the string to allow alignment. If neither (a) nor (b) apply, end " +
                    "alignment is not enforced.";

    private static final String SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME =
            "Search Only in Accessible Memory Blocks";
    private static final String SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DESCRIPTION =
            "If checked, this " +
                    "analyzer only searches in memory blocks that have at least one of the Read (R), Write " +
                    "(W), or Execute (X) permissions set to true. Enabling this option ensures that strings " +
                    "are not created in areas such as overlays or debug sections.";

    public static enum Encoding {
        Encoding_Big5IBM01142(1, "Big5IBM01142"),
        Encoding_Big5_HKSCSIBM01142(2, "Big5-HKSCSIBM01142"),
        Encoding_CESU_8(3, "CESU-8"),
        Encoding_EUC_JP(4, "EUC-JP"),
        Encoding_EUC_KR(5, "EUC-KR"),
        Encoding_GB18030(6, "GB18030"),
        Encoding_GB2312(7, "GB2312"),
        Encoding_GBK(8, "GBK"),
        Encoding_IBM_Thai(9, "IBM-Thai"),
        Encoding_IBM00858(10, "IBM00858"),
        Encoding_IBM01140(11, "IBM01140"),
        Encoding_IBM01141(12, "IBM01141"),
        Encoding_IBM01142(13, "IBM01142"),
        Encoding_IBM01143(14, "IBM01143"),
        Encoding_IBM01144(15, "IBM01144"),
        Encoding_IBM01145(16, "IBM01145"),
        Encoding_IBM01146(17, "IBM01146"),
        Encoding_IBM01147(18, "IBM01147"),
        Encoding_IBM01148(19, "IBM01148"),
        Encoding_IBM01149(20, "IBM01149"),
        Encoding_IBM037(21, "IBM037"),
        Encoding_IBM1026(22, "IBM1026"),
        Encoding_IBM1047(23, "IBM1047"),
        Encoding_IBM273(24, "IBM273"),
        Encoding_IBM277(25, "IBM277"),
        Encoding_IBM278(26, "IBM278"),
        Encoding_IBM280(27, "IBM280"),
        Encoding_IBM284(28, "IBM284"),
        Encoding_IBM285(29, "IBM285"),
        Encoding_IBM290(30, "IBM290"),
        Encoding_IBM297(31, "IBM297"),
        Encoding_IBM420(32, "IBM420"),
        Encoding_IBM424(33, "IBM424"),
        Encoding_IBM437(34, "IBM437"),
        Encoding_IBM500(35, "IBM500"),
        Encoding_IBM775(36, "IBM775"),
        Encoding_IBM850(37, "IBM850"),
        Encoding_IBM852(38, "IBM852"),
        Encoding_IBM855(39, "IBM855"),
        Encoding_IBM857(40, "IBM857"),
        Encoding_IBM860(41, "IBM860"),
        Encoding_IBM861(42, "IBM861"),
        Encoding_IBM862(43, "IBM862"),
        Encoding_IBM863(44, "IBM863"),
        Encoding_IBM864(45, "IBM864"),
        Encoding_IBM865(46, "IBM865"),
        Encoding_IBM866(47, "IBM866"),
        Encoding_IBM868(48, "IBM868"),
        Encoding_IBM869(49, "IBM869"),
        Encoding_IBM870(50, "IBM870"),
        Encoding_IBM871(51, "IBM871"),
        Encoding_IBM918(52, "IBM918"),
        Encoding_ISO_2022_CN(53, "ISO-2022-CN"),
        Encoding_ISO_2022_JP(54, "ISO-2022-JP"),
        Encoding_ISO_2022_JP_2(55, "ISO-2022-JP-2"),
        Encoding_ISO_2022_KR(56, "ISO-2022-KR"),
        Encoding_ISO_8859_1(57, "ISO-8859-1"),
        Encoding_ISO_8859_13(58, "ISO-8859-13"),
        Encoding_ISO_8859_15(59, "ISO-8859-15"),
        Encoding_ISO_8859_16(60, "ISO-8859-16"),
        Encoding_ISO_8859_2(61, "ISO-8859-2"),
        Encoding_ISO_8859_3(62, "ISO-8859-3"),
        Encoding_ISO_8859_4(63, "ISO-8859-4"),
        Encoding_ISO_8859_5(64, "ISO-8859-5"),
        Encoding_ISO_8859_6(65, "ISO-8859-6"),
        Encoding_ISO_8859_7(66, "ISO-8859-7"),
        Encoding_ISO_8859_8(67, "ISO-8859-8"),
        Encoding_ISO_8859_9(68, "ISO-8859-9"),
        Encoding_JIS_X0201(69, "JIS_X0201"),
        Encoding_JIS_X0212_1990(70, "JIS_X0212-1990"),
        Encoding_KOI8_R(71, "KOI8-R"),
        Encoding_KOI8_U(72, "KOI8-U"),
        Encoding_Shift_JIS(73, "Shift_JIS"),
        Encoding_TIS_620(74, "TIS-620"),
        Encoding_US_ASCII(75, "US-ASCII"),
        Encoding_UTF_16(76, "UTF-16"),
        Encoding_UTF_16BE(77, "UTF-16BE"),
        Encoding_UTF_16LE(78, "UTF-16LE"),
        Encoding_UTF_32(79, "UTF-32"),
        Encoding_UTF_32BE(80, "UTF-32BE"),
        Encoding_UTF_32LE(81, "UTF-32LE"),
        Encoding_UTF_8(82, "UTF-8"),
        Encoding_windows_1250(83, "windows-1250"),
        Encoding_windows_1251(84, "windows-1251"),
        Encoding_windows_1252(85, "windows-1252"),
        Encoding_windows_1253(86, "windows-1253"),
        Encoding_windows_1254(87, "windows-1254"),
        Encoding_windows_1255(88, "windows-1255"),
        Encoding_windows_1256(89, "windows-1256"),
        Encoding_windows_1257(90, "windows-1257"),
        Encoding_windows_1258(91, "windows-1258"),
        Encoding_windows_31j(92, "windows-31j"),
        Encoding_x_Big5_HKSCS_2001(93, "x-Big5-HKSCS-2001"),
        Encoding_x_Big5_Solaris(94, "x-Big5-Solaris"),
        Encoding_x_euc_jp_linux(95, "x-euc-jp-linux"),
        Encoding_x_EUC_TW(96, "x-EUC-TW"),
        Encoding_x_eucJP_Open(97, "x-eucJP-Open"),
        Encoding_x_IBM1006(98, "x-IBM1006"),
        Encoding_x_IBM1025(99, "x-IBM1025"),
        Encoding_x_IBM1046(100, "x-IBM1046"),
        Encoding_x_IBM1097(101, "x-IBM1097"),
        Encoding_x_IBM1098(102, "x-IBM1098"),
        Encoding_x_IBM1112(103, "x-IBM1112"),
        Encoding_x_IBM1122(104, "x-IBM1122"),
        Encoding_x_IBM1123(105, "x-IBM1123"),
        Encoding_x_IBM1124(106, "x-IBM1124"),
        Encoding_x_IBM1129(107, "x-IBM1129"),
        Encoding_x_IBM1166(108, "x-IBM1166"),
        Encoding_x_IBM1364(109, "x-IBM1364"),
        Encoding_x_IBM1381(110, "x-IBM1381"),
        Encoding_x_IBM1383(111, "x-IBM1383"),
        Encoding_x_IBM29626C(112, "x-IBM29626C"),
        Encoding_x_IBM300(113, "x-IBM300"),
        Encoding_x_IBM33722(114, "x-IBM33722"),
        Encoding_x_IBM737(115, "x-IBM737"),
        Encoding_x_IBM833(116, "x-IBM833"),
        Encoding_x_IBM834(117, "x-IBM834"),
        Encoding_x_IBM856(118, "x-IBM856"),
        Encoding_x_IBM874(119, "x-IBM874"),
        Encoding_x_IBM875(120, "x-IBM875"),
        Encoding_x_IBM921(121, "x-IBM921"),
        Encoding_x_IBM922(122, "x-IBM922"),
        Encoding_x_IBM930(123, "x-IBM930"),
        Encoding_x_IBM933(124, "x-IBM933"),
        Encoding_x_IBM935(125, "x-IBM935"),
        Encoding_x_IBM937(126, "x-IBM937"),
        Encoding_x_IBM939(127, "x-IBM939"),
        Encoding_x_IBM942(128, "x-IBM942"),
        Encoding_x_IBM942C(129, "x-IBM942C"),
        Encoding_x_IBM943(130, "x-IBM943"),
        Encoding_x_IBM943C(131, "x-IBM943C"),
        Encoding_x_IBM948(132, "x-IBM948"),
        Encoding_x_IBM949(133, "x-IBM949"),
        Encoding_x_IBM949C(134, "x-IBM949C"),
        Encoding_x_IBM950(135, "x-IBM950"),
        Encoding_x_IBM964(136, "x-IBM964"),
        Encoding_x_IBM970(137, "x-IBM970"),
        Encoding_x_ISCII91(138, "x-ISCII91"),
        Encoding_x_ISO_2022_CN_CNS(139, "x-ISO-2022-CN-CNS"),
        Encoding_x_ISO_2022_CN_GB(140, "x-ISO-2022-CN-GB"),
        Encoding_x_iso_8859_11(141, "x-iso-8859-11"),
        Encoding_x_JIS0208(142, "x-JIS0208"),
        Encoding_x_JISAutoDetect(143, "x-JISAutoDetect"),
        Encoding_x_Johab(144, "x-Johab"),
        Encoding_x_MacArabic(145, "x-MacArabic"),
        Encoding_x_MacCentralEurope(146, "x-MacCentralEurope"),
        Encoding_x_MacCroatian(147, "x-MacCroatian"),
        Encoding_x_MacCyrillic(148, "x-MacCyrillic"),
        Encoding_x_MacDingbat(149, "x-MacDingbat"),
        Encoding_x_MacGreek(150, "x-MacGreek"),
        Encoding_x_MacHebrew(151, "x-MacHebrew"),
        Encoding_x_MacIceland(152, "x-MacIceland"),
        Encoding_x_MacRoman(153, "x-MacRoman"),
        Encoding_x_MacRomania(154, "x-MacRomania"),
        Encoding_x_MacSymbol(155, "x-MacSymbol"),
        Encoding_x_MacThai(156, "x-MacThai"),
        Encoding_x_MacTurkish(157, "x-MacTurkish"),
        Encoding_x_MacUkraine(158, "x-MacUkraine"),
        Encoding_x_MS932_0213(159, "x-MS932_0213"),
        Encoding_x_MS950_HKSCS(160, "x-MS950-HKSCS"),
        Encoding_x_MS950_HKSCS_XP(161, "x-MS950-HKSCS-XP"),
        Encoding_x_mswin_936(162, "x-mswin-936"),
        Encoding_x_PCK(163, "x-PCK"),
        Encoding_x_SJIS_0213(164, "x-SJIS_0213"),
        Encoding_x_UTF_16LE_BOM(165, "x-UTF-16LE-BOM"),
        Encoding_X_UTF_32BE_BOM(166, "X-UTF-32BE-BOM"),
        Encoding_X_UTF_32LE_BOM(167, "X-UTF-32LE-BOM"),
        Encoding_x_windows_50220(168, "x-windows-50220"),
        Encoding_x_windows_50221(169, "x-windows-50221"),
        Encoding_x_windows_874(170, "x-windows-874"),
        Encoding_x_windows_949(171, "x-windows-949"),
        Encoding_x_windows_950(172, "x-windows-950"),
        Encoding_x_windows_iso2022jp(173, "x-windows-iso2022jp");
        private int encodingCode;
        private String encodingName;

        Encoding(int encodingCode, String encodingName) {
            this.encodingCode = encodingCode;
            this.encodingName = encodingName;
        }

        public String getEncodingName() {
            return this.encodingName;
        }
    }

    private static final Encoding ENCODING_DEFAULT_VALUE = Encoding.Encoding_UTF_8;
    private static final boolean REQUIRE_NULL_TERMINATION_DEFAULT_VALUE = true;
    private static final boolean ALL_CHAR_WIDTHS_DEFAULT_VALUE = false;
    private static final boolean ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT = true;
    private static final boolean ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT = true;
    private static final boolean SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT = true;
    private static StringsAnalyzer.Alignment[] alignmentChoices =
            new StringsAnalyzer.Alignment[] { StringsAnalyzer.Alignment.ALIGN_1, StringsAnalyzer.Alignment.ALIGN_2, StringsAnalyzer.Alignment.ALIGN_4 };
    private static StringsAnalyzer.Alignment START_ALIGNMENT_DEFAULT_VALUE = StringsAnalyzer.Alignment.ALIGN_1;
    private static int END_ALIGNMENT_DEFAULT_VALUE = 4;
    private static final StringsAnalyzer.MinStringLen MINIMUM_STRING_LENGTH_DEFAULT_VALUE = StringsAnalyzer.MinStringLen.LEN_5;

    private static final int ABSOLUTE_MIN_STR_LENGTH = NGramUtils.getMinimumStringLength();

    private String targetEncoding = ENCODING_DEFAULT_VALUE.getEncodingName();
    private int minStringLength = MINIMUM_STRING_LENGTH_DEFAULT_VALUE.getMinLength();
    private boolean requireNullEnd = REQUIRE_NULL_TERMINATION_DEFAULT_VALUE;
    private int startAlignment = START_ALIGNMENT_DEFAULT_VALUE.getAlignment();
    private int endAlignment = END_ALIGNMENT_DEFAULT_VALUE;
    private boolean allowStringCreationWithOffcutReferences =
            ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT;
    private boolean allowStringCreationWithExistringSubstring =
            ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT;
    private boolean searchOnlyAccessibleMemBlocks = SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT;

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

    void setStringEndAlignment(int alignment) {
        endAlignment = (alignment <= 0) ? 1 : alignment;
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

            if (searchOnlyAccessibleMemBlocks) {

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

                findStrings(program, intersecting, minStringLength, startAlignment, requireNullEnd, monitor);
            }


        } catch (CancelledException e) {
            throw e;
        }
        return true;
    }

    private boolean hasOffcut(Address startAddress, Address endAddress, Program program) {

        Address currentAddress = startAddress.next();
        while (currentAddress != null && currentAddress.compareTo(endAddress) <= 0) {

            if (program.getReferenceManager().hasReferencesTo(currentAddress)) {
                return true;
            }

            currentAddress = currentAddress.next();
        }

        return false;
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

        boolean hasOffcutReferences = false;
        if (!allowStringCreationWithOffcutReferences) {
            hasOffcutReferences = hasOffcut(start, end, program);
        }
//            // Only make a string if no offcut references or there are offcut references,
//            // but user says so
        if (hasOffcutReferences && !allowStringCreationWithOffcutReferences) {
            return;
        }
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
            recentDefinedString.setValue("charset", targetEncoding);

            Msg.trace(this, "Created string '" + bsfCandidate.getEncodedString() + "' at " + start);

            monitor.setMessage("Creating String at " + start);
        }
        catch (Exception e) {
            throw new AssertException("Unexpected exception", e);
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
    private void findStrings(final Program program, AddressSetView addressSet,
                             int minimumStringLength, int alignVal, boolean requireNullTermination, TaskMonitor monitor) {

        FoundStringCallback foundStringCallback =
                foundString -> createStringIfValid(foundString, program, addressSet, monitor);

        BSFStringSearcher searcher = new BSFStringSearcher(program, minimumStringLength, alignVal, requireNullTermination); //program, minimumStringLength, alignVal

        searcher.search(addressSet, foundStringCallback, true, monitor);
    }

    @Override
    public AnalysisOptionsUpdater getOptionsUpdater() {
        return super.getOptionsUpdater();
    }

    @Override
    public void registerOptions(Options options, Program program) {

        options.registerOption(ENCODING_OPTION_NAME,
                ENCODING_DEFAULT_VALUE, null, ENCODING_OPTION_DESCRIPTION);

        options.registerOption(MINIMUM_STRING_LENGTH_OPTION_NAME,
                MINIMUM_STRING_LENGTH_DEFAULT_VALUE, null, MINIMUM_STRING_LENGTH_OPTION_DESCRIPTION);

        options.registerOption(REQUIRE_NULL_TERMINATION_OPTION_NAME,
                REQUIRE_NULL_TERMINATION_DEFAULT_VALUE, null,
                REQUIRE_NULL_TERMINATION_OPTION_DESCRIPTION);

        options.registerOption(START_ALIGNMENT_OPTION_NAME, START_ALIGNMENT_DEFAULT_VALUE, null,
                START_ALIGNMENT_OPTION_DESCRIPTION);

        options.registerOption(END_ALIGNMENT_OPTION_NAME, END_ALIGNMENT_DEFAULT_VALUE, null,
                END_ALIGNMENT_OPTION_DESCRIPTION);

        options.registerOption(ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME,
                ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT, null,
                ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DESCRIPTION);

        options.registerOption(ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME,
                ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT, null,
                ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DESCRIPTION);

        options.registerOption(SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME,
                SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT, null,
                SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DESCRIPTION);
    }

    @Override
    public void optionsChanged(Options options, Program program) {

        minStringLength = options.getEnum(MINIMUM_STRING_LENGTH_OPTION_NAME,
                MINIMUM_STRING_LENGTH_DEFAULT_VALUE).getMinLength();

        requireNullEnd = options.getBoolean(REQUIRE_NULL_TERMINATION_OPTION_NAME,
                REQUIRE_NULL_TERMINATION_DEFAULT_VALUE);

        startAlignment = options.getEnum(START_ALIGNMENT_OPTION_NAME,
                START_ALIGNMENT_DEFAULT_VALUE).getAlignment();

        targetEncoding = options.getEnum(ENCODING_OPTION_NAME,
                ENCODING_DEFAULT_VALUE).getEncodingName();

        setStringEndAlignment(
                options.getInt(END_ALIGNMENT_OPTION_NAME, END_ALIGNMENT_DEFAULT_VALUE));

        allowStringCreationWithOffcutReferences =
                options.getBoolean(ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME,
                        ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT);

        allowStringCreationWithExistringSubstring =
                options.getBoolean(ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME,
                        ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT);

        searchOnlyAccessibleMemBlocks = options.getBoolean(SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME,
                SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT);
    }

}
