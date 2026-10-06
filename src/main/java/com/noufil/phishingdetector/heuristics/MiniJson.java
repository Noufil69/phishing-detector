package com.noufil.phishingdetector.heuristics;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A very small JSON reader for responses that come from other servers.
 *
 * The input is treated as untrusted:
 *  - nesting depth is limited, so a hostile "[[[[[..." cannot overflow the stack
 *  - an error never contains any of the input text
 *  - anything it cannot understand is reported as IllegalArgumentException("Invalid JSON")
 *
 * Produces Map, List, String, Double, Boolean or null.
 */
final class MiniJson {

    static final int MAX_DEPTH = 32;

    private MiniJson() {
    }

    /** @throws IllegalArgumentException if the text is not valid JSON */
    static Object parse(String json) {
        if (json == null) {
            throw new IllegalArgumentException("Invalid JSON");
        }
        return new Reader(json).readDocument();
    }

    private static final class Reader {

        private final String text;
        private int pos = 0;

        Reader(String text) {
            this.text = text;
        }

        Object readDocument() {
            Object value = readValue(0);
            skipWhitespace();
            if (pos != text.length()) {
                throw invalid();
            }
            return value;
        }

        private IllegalArgumentException invalid() {
            return new IllegalArgumentException("Invalid JSON");
        }

        private void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private Object readValue(int depth) {
            if (depth > MAX_DEPTH) {
                throw invalid();
            }
            skipWhitespace();
            if (pos >= text.length()) {
                throw invalid();
            }
            char c = text.charAt(pos);
            return switch (c) {
                case '{' -> readObject(depth);
                case '[' -> readArray(depth);
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> readNumber();
            };
        }

        private Object readLiteral(String literal, Object value) {
            if (!text.startsWith(literal, pos)) {
                throw invalid();
            }
            pos += literal.length();
            return value;
        }

        private Object readNumber() {
            int start = pos;
            while (pos < text.length() && "+-0123456789.eE".indexOf(text.charAt(pos)) >= 0) {
                pos++;
            }
            if (start == pos) {
                throw invalid();
            }
            try {
                return Double.parseDouble(text.substring(start, pos));
            } catch (NumberFormatException e) {
                throw invalid();
            }
        }

        private String readString() {
            if (pos >= text.length() || text.charAt(pos) != '"') {
                throw invalid();
            }
            pos++;
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (pos >= text.length()) {
                    throw invalid();
                }
                char c = text.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (pos >= text.length()) {
                    throw invalid();
                }
                char escape = text.charAt(pos++);
                switch (escape) {
                    case '"', '\\', '/' -> sb.append(escape);
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        if (pos + 4 > text.length()) {
                            throw invalid();
                        }
                        try {
                            sb.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
                        } catch (NumberFormatException e) {
                            throw invalid();
                        }
                        pos += 4;
                    }
                    default -> throw invalid();
                }
            }
        }

        private Map<String, Object> readObject(int depth) {
            pos++; // skip '{'
            Map<String, Object> map = new LinkedHashMap<>();
            skipWhitespace();
            if (pos < text.length() && text.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = readString();
                skipWhitespace();
                if (pos >= text.length() || text.charAt(pos) != ':') {
                    throw invalid();
                }
                pos++;
                map.put(key, readValue(depth + 1));
                skipWhitespace();
                if (pos >= text.length()) {
                    throw invalid();
                }
                char c = text.charAt(pos++);
                if (c == '}') {
                    return map;
                }
                if (c != ',') {
                    throw invalid();
                }
            }
        }

        private List<Object> readArray(int depth) {
            pos++; // skip '['
            List<Object> list = new ArrayList<>();
            skipWhitespace();
            if (pos < text.length() && text.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(readValue(depth + 1));
                skipWhitespace();
                if (pos >= text.length()) {
                    throw invalid();
                }
                char c = text.charAt(pos++);
                if (c == ']') {
                    return list;
                }
                if (c != ',') {
                    throw invalid();
                }
            }
        }
    }
}