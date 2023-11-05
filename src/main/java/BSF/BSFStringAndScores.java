package BSF;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class BSFStringAndScores {

    private byte[] originalBytes;
    private HashMap<String, Double> encodingScores = new HashMap<>();

    public BSFStringAndScores(byte[] bytes) {
        this.originalBytes = bytes;
    }

    public byte[] getOriginalBytes() {
        return originalBytes;
    }

    public void addEncodingToScores(String encoding, double score) {
        this.encodingScores.put(encoding, score);
    }

    public String getBestMatchingEncoding() {
        return Collections.max(this.encodingScores.entrySet(), Map.Entry.comparingByValue()).getKey();
    }

    public String getEncodedString(String targetEncoding) {
        String bestEncoding = targetEncoding;//this.getBestMatchingEncoding();
        try {
            return new String(this.originalBytes, bestEncoding);
        } catch (UnsupportedEncodingException e) {
            return "ERROR DECODING STRING WITH ENCODING: " + bestEncoding;
        }
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(originalBytes);
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("OrigBytes =").append(Arrays.toString(originalBytes));
        for (Map.Entry<String, Double> e : this.encodingScores.entrySet()) {
            builder.append(e.getKey()).append(":").append(e.getValue()).append(",,");
        }

        return builder.toString();
    }


}
