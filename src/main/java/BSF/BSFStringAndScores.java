package BSF;

import java.util.Collections;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Map;

public class BSFStringAndScores {

    private String originalString = "", scoredString = "";
    private HashMap<String, Double> encodingScores = new HashMap<>();

    public BSFStringAndScores(String string) {
        this.originalString = string;
        this.scoredString = this.normalizeSpaces(this.originalString);
    }

    private String normalizeSpaces(String str) {
        // Remove leading and trailing spaces
        String newStr = str;
        newStr = newStr.trim();

        // Collapse consecutive spaces into 1 space
        newStr = newStr.replaceAll(" {2,}", " ");

        // Collapse consecutive tabs into 1 tab
        newStr = newStr.replaceAll("\t{2,}", "\t");

        return newStr;
    }

    public int getScoredStringLength() {
        return this.scoredString.length();
    }

    public String getScoredString() {
        return scoredString;
    }

    public void addEncodingToScores(String encoding, double score) {
        this.encodingScores.put(encoding, score);
    }

    public String getBestMatchingEncoding() {
        return Collections.max(this.encodingScores.entrySet(), Map.Entry.comparingByValue()).getKey();
    }

    @Override
    public int hashCode() {
        return originalString.hashCode();
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("OrigString =").append(originalString);
        builder.append(",ScoredString =").append(scoredString).append(",,");
        for (Map.Entry<String, Double> e : this.encodingScores.entrySet()) {
            builder.append(e.getKey()).append(":").append(e.getValue()).append(",,");
        }

        return builder.toString();
    }


}
