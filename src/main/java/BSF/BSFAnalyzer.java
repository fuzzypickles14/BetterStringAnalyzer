package BSF;

import ghidra.app.plugin.core.analysis.AnalysisOptionsUpdater;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.io.IOException;

public class BSFAnalyzer extends AbstractAnalyzer {
    private static final String NAME = "Better String Finder";
    private static final String DESCRIPTION = "This analyzer searches for strings with non-ASCII encodings using International Components of Unicode (ICU)'s library.";

    public BSFAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after().after());
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, ghidra.app.util.importer.MessageLog log) throws CancelledException {
        return false;
    }

    @Override
    public AnalysisOptionsUpdater getOptionsUpdater() {
        return super.getOptionsUpdater();
    }
}
