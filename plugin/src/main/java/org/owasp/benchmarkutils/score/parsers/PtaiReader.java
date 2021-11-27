package org.owasp.benchmarkutils.score.parsers;

import java.io.File;
import java.io.FileInputStream;
import java.text.SimpleDateFormat;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public class PtaiReader extends Reader {
    // This reader supports PT Application Inspector reports

    public TestSuiteResults parse(File file) throws Exception {
        System.out.println("Parse started");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        InputSource is = new InputSource(new FileInputStream(file));
        Document doc = builder.parse(is);

        TestSuiteResults tr = new TestSuiteResults("PTAI", true, TestSuiteResults.ToolType.SAST);

        Node scanReportData = doc.getDocumentElement();
        Node scanInfo = getNamedChild("ScanInfo", scanReportData);
        Node items = getNamedChild("Items", scanReportData);
        Node settings = getNamedChild("Settings", scanInfo);
        List<Node> scanSettings = getNamedChildren("ScanSetting", settings);

        // Get scan statistics from XML report
        for (Node scanSetting : scanSettings) {
            Node nameNode = getNamedChild("Name", scanSetting);
            Node valueNode = getNamedChild("Value", scanSetting);
            if ("Version".equalsIgnoreCase(nameNode.getNodeValue())
                    || "Версия".equalsIgnoreCase(nameNode.getNodeValue()))
                tr.setToolVersion(valueNode.getTextContent());
            else if ("Scan duration".equalsIgnoreCase(nameNode.getNodeValue())
                    || "Время сканирования".equalsIgnoreCase(nameNode.getNodeValue())) {
                String scanTime = valueNode.getTextContent();
                long duration =
                        DateUtils.parseDate(scanTime, new String[] {"HH:mm:ss"})
                                .toInstant()
                                .toEpochMilli();
                long reference =
                        new SimpleDateFormat("HH:mm:ss")
                                .parse("00:00:00")
                                .toInstant()
                                .toEpochMilli();
                tr.setTime(TestSuiteResults.formatTime(String.valueOf(duration - reference)));
            }
        }

        for (Node node : getNamedChildren("VulnerabilityBase", items)) {
            TestCaseResult tcr = parseVulnerability(node);
            if (null != tcr) tr.put(tcr);
        }
        return tr;
    }

    static final int CWE_PATH_TRAVERSAL = 22;
    static final int PTAI_CWE_EXTERNAL_FILEPATH_CONTROL = 73;
    static final int CWE_REVERSIBLE_HASH = 328;
    static final int PTAI_CWE_INADEQUATE_ENCRYPTION_STRENGTH = 326;
    static final int CWE_USE_OF_BROKEN_OR_RISKY_CRYPTOGRAPHIC_ALGORITHM = 327;
    static final int CWE_XPATH_INJECTION = 643;
    static final int PTAI_CWE_BLIND_XPATH_INJECTION = 91;

    private void fixCwe(TestCaseResult tcr) {
        // PT AI detects AFX's that OWASP treats as path traversals. Need to fix CWE 73 to 22
        if (PTAI_CWE_EXTERNAL_FILEPATH_CONTROL == tcr.getCWE()) tcr.setCWE(CWE_PATH_TRAVERSAL);
        if (PTAI_CWE_INADEQUATE_ENCRYPTION_STRENGTH == tcr.getCWE()) {
            if ("Weak Cryptographic Hash".equalsIgnoreCase(tcr.getCategory())
                    || "Уязвимые функции хэширования".equalsIgnoreCase(tcr.getCategory()))
                tcr.setCWE(CWE_REVERSIBLE_HASH);
            else if ("Weak Cryptographic Algorithm".equalsIgnoreCase(tcr.getCategory())
                    || "Нестойкий алгоритм шифрования".equalsIgnoreCase(tcr.getCategory()))
                tcr.setCWE(CWE_USE_OF_BROKEN_OR_RISKY_CRYPTOGRAPHIC_ALGORITHM);
        }
        if (PTAI_CWE_BLIND_XPATH_INJECTION == tcr.getCWE()) tcr.setCWE(CWE_XPATH_INJECTION);
    }

    private TestCaseResult parseVulnerability(Node node) {
        try {
            TestCaseResult tcr = new TestCaseResult();
            // Get vulnerable file name
            Node childNode = getNamedChild("SourceFile", node);
            if (null == childNode) return null;
            String filename = childNode.getTextContent();
            String classname = filename.substring(filename.lastIndexOf("\\") + 1).trim();
            classname = classname.replaceAll(" : [0-9]+$", "");
            // Check if file is a test suite member
            if (!classname.startsWith(BenchmarkScore.TESTCASENAME)) return null;
            // Set test number
            String testNumber =
                    classname.substring(
                            BenchmarkScore.TESTCASENAME.length(), classname.lastIndexOf('.'));
            tcr.setNumber(Integer.parseInt(testNumber));
            // Set CWE
            childNode = getNamedChild("CweId", node);
            if (null == childNode) return null;
            tcr.setCWE(Integer.parseInt(childNode.getTextContent()));
            // Set category
            childNode = getNamedChild("Type", node);
            if (null == childNode) throw new Exception();
            String type = getNamedChild("Value", childNode).getTextContent();
            if (StringUtils.isEmpty(type)) throw new Exception();
            tcr.setCategory(type);

            fixCwe(tcr);

            return tcr;
        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }
}
