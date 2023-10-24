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
        byte[] stringAsBytes = stringAndScores.getScoredString().getBytes();
        detector.setText(stringAsBytes);
        CharsetMatch matches[] = detector.detectAll();
        System.out.println(stringAndScores);
    }

    public void scoreBSFString(byte[] bytes) {
        CharsetDetector detector = new CharsetDetector();
        detector.setText(bytes);
        CharsetMatch matches[] = detector.detectAll();
        try {
            System.out.println(new String(bytes, matches[0].getName()));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

}
