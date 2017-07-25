package org.owasp.benchmark.helpers;

public class NistHelper {
	
	// SARD-testsuite-105-c#	path='000/199/332/cwe_327__I_readline__F_no_filtering__S_md5__0_File1.cs'
	// SARD-testsuite-87		path='000/123/327/CWE111_Unsafe_JNI__console_01.java'
	
	static public Integer getTestNumberFromFilename(String filename) {
		String token1 = filename.substring(4, 7);
		String token2 = filename.substring(8, 11);
		
		Integer testNumber = 0;
		try {
			testNumber = Integer.parseInt(token1+token2);
		} catch (Exception e) {
			
		}
		
		return testNumber;
	}

	public static String getTestNameFromFilename(String filename) {
		return filename.substring(0, 7);
	}


	public static String getTestTypeFromFilename(String filename) {
		String cwe = getTestCWEFromFilename(filename);
		
		return "CWE-" + cwe;
	}

	public static String getTestCWEFromFilename(String filename) {
		String cwe = "";
		
		try {
			cwe = filename.substring(15);
			if (cwe.charAt(0) == '_') {
				cwe = cwe.substring(1);
			}
			
			cwe = cwe.substring(0, 3);
			cwe = cwe.replace("_", "");
			
			if (cwe.startsWith("0")) {
				cwe = cwe.substring(1, 2);
			}
		} catch (Exception e) {
			//e.printStackTrace();
			cwe = "0";
		}

		
		return cwe;
	}
}
