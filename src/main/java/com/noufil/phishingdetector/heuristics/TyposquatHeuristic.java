package com.noufil.phishingdetector.heuristics;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Component;

import com.noufil.phishingdetector.model.RiskFactor;

/**
 * Heuristic 2: typosquatting / brand impersonation.
 *
 * Compares the registrable part of the domain (the "paypal" in paypal.com)
 * against a list of commonly impersonated brands. Pure string work, no network.
 *
 * Known limitations (intentional, documented in docs/TRD.md):
 *  - The brand list is small and hand-picked.
 *  - It cannot tell the real brand TLD from a fake one (paypal.com vs paypal.xyz).
 *    The Structural check covers suspicious TLDs.
 */
@Component
public class TyposquatHeuristic implements HeuristicCheck {

    static final String NAME = "Typosquat";

    static final int POINTS_LOOKALIKE_CHARS = 90;
    static final int POINTS_ONE_EDIT = 70;
    static final int POINTS_TWO_EDITS = 40;
    static final int POINTS_BRAND_IN_NAME = 50;

    // One edit on a short brand causes too many false alarms (chase vs case), so
    // edit distance is only used for longer brand names.
    static final int MIN_BRAND_LENGTH_ONE_EDIT = 6;
    static final int MIN_BRAND_LENGTH_TWO_EDITS = 9;

    private static final List<String> BRANDS = List.of(
            "paypal", "google", "microsoft", "amazon", "apple", "facebook",
            "instagram", "whatsapp", "netflix", "twitter", "linkedin", "youtube",
            "github", "dropbox", "ebay", "chase", "wellsfargo", "bankofamerica",
            "citibank", "hsbc", "binance", "coinbase", "openai", "anthropic",
            "spotify", "adobe", "outlook", "icloud", "telegram", "tiktok",
            "discord", "steam", "paytm", "easypaisa", "jazzcash", "hbl",
            "ubl", "daraz", "meezanbank");

    private static final Set<String> BRAND_SET = Set.copyOf(BRANDS);

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public RiskFactor evaluate(String url) {
        Optional<String> hostOpt = HostExtractor.extractHost(url);
        if (hostOpt.isEmpty()) {
            return RiskFactor.of(NAME, 0, "No valid host name to compare against known brands");
        }
        String host = hostOpt.get();

        if (HostExtractor.isIpHost(host)) {
            return RiskFactor.of(NAME, 0, "Not applicable to IP address hosts");
        }

        String[] labels = host.split("\\.");
        int registrableCount = HostExtractor.registrableLabelCount(labels);
        int registrableIndex = Math.max(0, labels.length - registrableCount);

        String rawName = labels[registrableIndex];

        // The domain really is the brand's own name (TLD is not verified here).
        if (BRAND_SET.contains(rawName)) {
            return RiskFactor.of(NAME, 0, "Domain name is the known brand '" + rawName + "'");
        }

        // "xn--" labels are decoded and reduced to the plain letters they imitate,
        // so a paypal written with a Cyrillic letter a is compared as "paypal".
        String name = Confusables.comparable(rawName);
        List<String> subdomainLabels = Arrays.stream(labels, 0, registrableIndex)
                .map(Confusables::comparable)
                .toList();

        if (BRAND_SET.contains(name)) {
            return RiskFactor.of(NAME, POINTS_LOOKALIKE_CHARS,
                    "Domain name uses look-alike letters (accents or another alphabet) to imitate '" + name + "'");
        }

        int bestScore = 0;
        String bestReason = null;

        for (String brand : BRANDS) {
            int score = 0;
            String reason = null;

            int distance = smallestDistance(name, brand);
            if (distance == 0) {
                score = POINTS_LOOKALIKE_CHARS;
                reason = "Domain name looks like '" + brand + "' with look-alike characters swapped in";
            } else if (distance == 1 && brand.length() >= MIN_BRAND_LENGTH_ONE_EDIT) {
                score = POINTS_ONE_EDIT;
                reason = "Domain name is one character away from '" + brand + "'";
            } else if (distance == 2 && brand.length() >= MIN_BRAND_LENGTH_TWO_EDITS) {
                score = POINTS_TWO_EDITS;
                reason = "Domain name is two characters away from '" + brand + "'";
            }

            if (score < POINTS_BRAND_IN_NAME) {
                if (subdomainLabels.contains(brand)) {
                    score = POINTS_BRAND_IN_NAME;
                    reason = "Uses the brand name '" + brand + "' in a subdomain to look official";
                } else if (Arrays.asList(name.split("-")).contains(brand)) {
                    score = POINTS_BRAND_IN_NAME;
                    reason = "Domain name contains the brand name '" + brand + "' but is not the brand";
                }
            }

            if (score > bestScore) {
                bestScore = score;
                bestReason = reason;
            }
        }

        if (bestScore == 0) {
            return RiskFactor.of(NAME, 0, "No look-alike of a known brand found");
        }
        return RiskFactor.of(NAME, bestScore, bestReason);
    }

    /**
     * Smallest edit distance between the brand and the name, trying the name as
     * written and with common look-alike substitutions undone
     * (0 for o, 1 for l or i, 3 for e, 4 for a, 5 for s, 7 for t, rn for m, vv for w).
     */
    private int smallestDistance(String name, String brand) {
        String base = name.replace("rn", "m").replace("vv", "w");
        int best = levenshtein(name, brand);
        best = Math.min(best, levenshtein(undoDigits(base, 'l'), brand));
        best = Math.min(best, levenshtein(undoDigits(base, 'i'), brand));
        return best;
    }

    private String undoDigits(String s, char oneReplacement) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '0' -> sb.append('o');
                case '1' -> sb.append(oneReplacement);
                case '3' -> sb.append('e');
                case '4' -> sb.append('a');
                case '5' -> sb.append('s');
                case '7' -> sb.append('t');
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Classic Levenshtein edit distance (insert, delete, substitute), two-row version. */
    static int levenshtein(String a, String b) {
        int[] previous = new int[b.length() + 1];
        int[] current = new int[b.length() + 1];

        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }

        for (int i = 1; i <= a.length(); i++) {
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                current[j] = Math.min(
                        Math.min(current[j - 1] + 1, previous[j] + 1),
                        previous[j - 1] + cost);
            }
            int[] swap = previous;
            previous = current;
            current = swap;
        }
        return previous[b.length()];
    }
}
