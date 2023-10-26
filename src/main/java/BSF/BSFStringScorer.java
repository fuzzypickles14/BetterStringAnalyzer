package BSF;

import com.ibm.icu.text.CharsetDetector;
import com.ibm.icu.text.CharsetMatch;

import java.io.UnsupportedEncodingException;

public class BSFStringScorer {

    private double minimumThreshold = 95d;
    public BSFStringScorer() {

    }

    public void scoreBSFString(BSFStringAndScores stringAndScores) {
        CharsetDetector detector = new CharsetDetector();
        detector.setText(stringAndScores.getOriginalBytes());
        CharsetMatch matches[] = detector.detectAll();
        for (CharsetMatch match : matches) {
            stringAndScores.addEncodingToScores(match.getName(), match.getConfidence());
        }
    }
}
