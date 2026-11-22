package com.atm.tests;

/**
 * 零依赖极简测试框架：assertX 失败抛出 AssertionError，TestRunner 统一统计。
 */
public abstract class AtmTest {

    protected int checks;

    public abstract String name();

    public abstract void run() throws Exception;

    protected void check(boolean cond, String message) {
        checks++;
        if (!cond) {
            throw new AssertionError(message);
        }
    }

    protected void checkEq(Object actual, Object expected, String message) {
        checks++;
        if (actual == null ? expected != null : !actual.equals(expected)) {
            throw new AssertionError(message + " — expected=<" + expected + "> actual=<" + actual + ">");
        }
    }

    protected void checkEq(long actual, long expected, String message) {
        checks++;
        if (actual != expected) {
            throw new AssertionError(message + " — expected=<" + expected + "> actual=<" + actual + ">");
        }
    }

    protected void fail(String message) {
        throw new AssertionError(message);
    }

    public int checks() {
        return checks;
    }
}
