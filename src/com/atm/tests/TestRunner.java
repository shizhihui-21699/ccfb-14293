package com.atm.tests;

import java.util.ArrayList;
import java.util.List;

/**
 * 测试运行器：收集全部测试套件，逐个执行，打印汇总。
 * 退出码 0 = 全部通过；非 0 = 存在失败（CI 友好）。
 */
public final class TestRunner {

    public record SuiteResult(String suite, int passed, int failed, List<String> failures) {
    }

    public static void main(String[] args) {
        List<Class<? extends AtmTest>> suites = List.of(
                ProtocolCryptoTest.class,
                PairingTest.class,
                BlackBoxAttackTest.class,
                OfflineTest.class,
                LifecycleTest.class);

        int totalPass = 0;
        int totalFail = 0;
        int totalChecks = 0;
        List<String> failureDetails = new ArrayList<>();

        for (Class<? extends AtmTest> suite : suites) {
            System.out.println("\n===== " + suite.getSimpleName() + " =====");
            // 每个套件类通过静态 factory() 提供用例列表
            try {
                @SuppressWarnings("unchecked")
                java.lang.reflect.Method m = suite.getMethod("suite");
                List<AtmTest> tests = (List<AtmTest>) m.invoke(null);
                for (AtmTest t : tests) {
                    try {
                        t.run();
                        totalPass++;
                        totalChecks += t.checks();
                        System.out.printf("  [PASS] %-60s (%d checks)%n", t.name(), t.checks());
                    } catch (Throwable e) {
                        totalFail++;
                        String detail = t.name() + " -> " + e;
                        failureDetails.add(detail);
                        System.out.printf("  [FAIL] %-60s %s%n", t.name(), e);
                    }
                }
            } catch (Exception e) {
                totalFail++;
                failureDetails.add(suite.getSimpleName() + " suite error: " + e);
                System.out.println("  [ERROR] cannot build suite: " + e);
            }
        }

        System.out.println("\n========== SUMMARY ==========");
        System.out.printf("tests: %d passed, %d failed, %d assertions%n",
                totalPass, totalFail, totalChecks);
        if (!failureDetails.isEmpty()) {
            System.out.println("\nFailures:");
            failureDetails.forEach(f -> System.out.println("  - " + f));
        }
        System.exit(totalFail == 0 ? 0 : 1);
    }
}
