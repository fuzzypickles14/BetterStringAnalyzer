package BSF;

import ghidra.util.ascii.CharSetRecognizer;

public class BSFCharSetRecognizer implements CharSetRecognizer {
    @Override
    public boolean contains(int c) {
        return ((c >= ' ') && (c <= 0xFF)) || (c == 0x0d) || (c == 0x0a) || (c == 0x09);
    }
}
