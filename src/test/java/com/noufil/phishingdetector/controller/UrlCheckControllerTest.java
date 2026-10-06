package com.noufil.phishingdetector.controller;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.noufil.phishingdetector.heuristics.HeuristicCheck;
import com.noufil.phishingdetector.model.RiskFactor;
import com.noufil.phishingdetector.model.RiskLevel;
import com.noufil.phishingdetector.service.ScoreAggregator;
import com.noufil.phishingdetector.service.ScoringConfig;
import com.noufil.phishingdetector.service.UrlCheckService;

/** Calls the controller method directly, with stand-in checks, so nothing touches the network. */
class UrlCheckControllerTest {

    /** Records every URL it is asked about and returns a fixed score. */
    private static final class Recorder implements HeuristicCheck {
        final List<String> seen = new ArrayList<>();
        private final String name;
        private final int score;

        Recorder(String name, int score) {
            this.name = name;
            this.score = score;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public RiskFactor evaluate(String url) {
            seen.add(url);
            return RiskFactor.of(name, score, "fixed reason");
        }
    }

    private static UrlCheckController controllerWith(HeuristicCheck... checks) {
        return new UrlCheckController(
                new UrlCheckService(List.of(checks), new ScoreAggregator(ScoringConfig.defaults())));
    }

    @Test
    void aValidUrlRunsTheChecksAndReturnsTheVerdict() {
        UrlCheckController controller = controllerWith(new Recorder("Typosquat", 70));

        CheckResponse response = controller.check(new CheckRequest("https://paypa1.com/login"));

        assertEquals(63, response.score());
        assertEquals(RiskLevel.HIGH, response.level());
        assertEquals("paypa1.com", response.host());
        assertEquals(1, response.factors().size());
        assertEquals("Typosquat", response.factors().get(0).check());
    }

    @Test
    void theChecksReceiveTheTrimmedUrl() {
        Recorder recorder = new Recorder("Structural", 0);
        controllerWith(recorder).check(new CheckRequest("  https://example.com/a  "));
        assertEquals(List.of("https://example.com/a"), recorder.seen);
    }

    @Test
    void aUnicodeDomainIsReportedInItsAsciiForm() {
        CheckResponse response = controllerWith(new Recorder("Structural", 0))
                .check(new CheckRequest("https://p\u0430ypal.com/login"));
        assertEquals("xn--pypal-4ve.com", response.host());
    }

    @Test
    void theResponseNeverContainsThePathOrQueryThatWasSubmitted() {
        CheckResponse response = controllerWith(new Recorder("Structural", 0))
                .check(new CheckRequest("https://example.com/secret-path-xyz?token=abc123"));
        String everything = response.toString();
        assertFalse(everything.contains("secret-path-xyz"));
        assertFalse(everything.contains("abc123"));
    }

    @Test
    void invalidInputIsRejectedBeforeAnyCheckRuns() {
        Recorder recorder = new Recorder("Structural", 0);
        UrlCheckController controller = controllerWith(recorder);

        assertThrows(InvalidUrlException.class, () -> controller.check(new CheckRequest("")));
        assertThrows(InvalidUrlException.class, () -> controller.check(new CheckRequest(null)));
        assertThrows(InvalidUrlException.class, () -> controller.check(new CheckRequest("ftp://example.com/x")));
        assertThrows(InvalidUrlException.class, () -> controller.check(new CheckRequest("not a url")));
        assertThrows(InvalidUrlException.class, () -> controller.check(null));

        assertTrue(recorder.seen.isEmpty());
    }

    @Test
    void aFailingCheckStillGivesAnAnswerWithANote() {
        HeuristicCheck exploding = new HeuristicCheck() {
            @Override
            public String getName() {
                return "Exploding";
            }

            @Override
            public RiskFactor evaluate(String url) {
                throw new IllegalStateException("boom");
            }
        };
        CheckResponse response = controllerWith(exploding, new Recorder("Typosquat", 50))
                .check(new CheckRequest("https://example.com"));

        assertEquals(1, response.checksRun());
        assertEquals(2, response.checksTotal());
        assertEquals("Only 1 of 2 checks could run, so this result is less complete.", response.note());
        assertEquals(45, response.score());
    }
}