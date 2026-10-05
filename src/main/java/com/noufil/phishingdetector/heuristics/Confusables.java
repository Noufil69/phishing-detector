package com.noufil.phishingdetector.heuristics;

import java.net.IDN;
import java.text.Normalizer;
import java.util.Locale;
import java.util.Map;

/**
 * Turns look-alike letters into the plain Latin letters they imitate, so that
 * a "paypal" written with a Cyrillic letter a (U+0430) can be compared with "paypal".
 *
 * This is a small hand-picked table of the most commonly abused characters, not
 * the full Unicode confusables list. It is a heuristic aid, not a guarantee.
 */
final class Confusables {

    private static final Map<Character, String> LOOKALIKES = Map.ofEntries(
            // Cyrillic
            Map.entry('\u0430', "a"), Map.entry('\u0441', "c"), Map.entry('\u0435', "e"),
            Map.entry('\u043e', "o"), Map.entry('\u0440', "p"), Map.entry('\u0445', "x"),
            Map.entry('\u0443', "y"), Map.entry('\u0456', "i"), Map.entry('\u0458', "j"),
            Map.entry('\u0455', "s"), Map.entry('\u0501', "d"), Map.entry('\u04bb', "h"),
            Map.entry('\u051b', "q"), Map.entry('\u051d', "w"), Map.entry('\u04cf', "l"),
            // Greek
            Map.entry('\u03bf', "o"), Map.entry('\u03b1', "a"), Map.entry('\u03bd', "v"),
            Map.entry('\u03c1', "p"), Map.entry('\u03b9', "i"), Map.entry('\u03ba', "k"),
            Map.entry('\u03c5', "u"), Map.entry('\u03f2', "c"),
            // Latin letters that do not decompose into a base letter plus an accent
            Map.entry('\u0131', "i"), Map.entry('\u0261', "g"), Map.entry('\u00f8', "o"),
            Map.entry('\u0142', "l"), Map.entry('\u0111', "d"), Map.entry('\u0127', "h"),
            Map.entry('\u00e6', "ae"), Map.entry('\u217c', "l")
    );

    private Confusables() {
    }

    /** Lower-cases, removes accents, and replaces known look-alike letters. */
    static String skeleton(String text) {
        String decomposed = Normalizer.normalize(text.toLowerCase(Locale.ROOT), Normalizer.Form.NFD);
        StringBuilder sb = new StringBuilder(decomposed.length());
        for (int i = 0; i < decomposed.length(); i++) {
            char c = decomposed.charAt(i);
            if (Character.getType(c) == Character.NON_SPACING_MARK) {
                continue;
            }
            String replacement = LOOKALIKES.get(c);
            sb.append(replacement != null ? replacement : String.valueOf(c));
        }
        return sb.toString();
    }

    /**
     * The form of a host label that should be compared with brand names. Plain
     * labels come back unchanged. "xn--" labels are decoded back to Unicode and
     * reduced to their look-alike skeleton.
     */
    static String comparable(String label) {
        if (!label.startsWith("xn--")) {
            return label;
        }
        return skeleton(IDN.toUnicode(label, IDN.ALLOW_UNASSIGNED));
    }
}