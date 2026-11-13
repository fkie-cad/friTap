package com.fritap.attributionfixture.common;

/** Minimal ordered, single-line JSON object writer (org.json escapes '/' which hurts readability). */
final class JsonLine {
    private final StringBuilder out = new StringBuilder("{");

    JsonLine put(String key, String value) {
        return raw(key, quote(value));
    }

    JsonLine put(String key, long value) {
        return raw(key, Long.toString(value));
    }

    JsonLine put(String key, boolean value) {
        return raw(key, Boolean.toString(value));
    }

    @Override
    public String toString() {
        return out.toString() + "}";
    }

    private JsonLine raw(String key, String encodedValue) {
        if (out.length() > 1) out.append(',');
        out.append(quote(key)).append(':').append(encodedValue);
        return this;
    }

    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : (s == null ? "" : s).toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
}
