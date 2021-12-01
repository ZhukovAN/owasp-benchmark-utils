/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Yuuki Endo / Jason Khoo
 * @created 2020
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class CheckmarxSASTReader extends Reader {

    private static int cweLookup(String checkerKey) {
        //    checkerKey = checkerKey.replace("-SECOND-ORDER", "");

        switch (checkerKey) {
            case "SQL Injection":
                return 89;
            case "SQL Injection Evasion Attack":
                return 89;
            case "Reflected XSS All Clients":
                return 79;
            case "Command Injection":
                return 78;
            case "Stored XSS":
                return 79;
            case "LDAP Injection":
                return 90;
            case "Use of a One Way Hash with a Predictable Salt":
                return 328;
            case "Sensitive Cookie in HTTPS Session Without Secure Attribute":
                return 614;
            case "Relative Path Traversal":
                return 22;
            case "Trust Boundary Violation":
                return 501;
            case "Use of Broken or Risky Cryptographic Algorithm":
                return 327;
            case "Use of Non Cryptographic Random":
                return 330;
            case "XPath Injection":
                return 643;
        }
        return 0;
    }

    public TestSuiteResults parse(File f) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("CxSAST", true, TestSuiteResults.ToolType.SAST);

        java.io.Reader inReader = new java.io.FileReader(f);
        Iterable<CSVRecord> records = CSVFormat.RFC4180.withFirstRecordAsHeader().parse(inReader);
        for (CSVRecord record : records) {
            String query = record.get("Query");
            String srcFileName = record.get("SrcFileName");

            TestCaseResult tcr = new TestCaseResult();
            tcr.setCategory(query);
            int cwe = cweLookup(query);
            if (0 == cwe) continue;
            tcr.setCWE(cwe);
            Pattern testCasePattern =
                    Pattern.compile(
                            BenchmarkScore.TESTCASENAME
                                    + "[0-9]{"
                                    + BenchmarkScore.TESTIDLENGTH
                                    + "}");
            Matcher testCaseMatcher = testCasePattern.matcher(srcFileName);
            if (testCaseMatcher.find()) {
                String testCase = testCaseMatcher.group(0);
                // System.out.println("testCase = "+testCase+" Test Num =
                // "+testCase.substring(testCase.length()-Utils.TESTCASE_DIGITS,
                // testCase.length())); // For debugging YE
                tcr.setTestCaseName(testCase);
                // BenchmarkTest00000 - BenchmarkTest99999
                tcr.setNumber(
                        Integer.parseInt(
                                testCase.substring(
                                        testCase.length() - BenchmarkScore.TESTIDLENGTH)));
                tr.put(tcr);
            }
        }
        tr.setTime("100");
        return tr;
    }
}
