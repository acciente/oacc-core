/*
 * Copyright 2009-2014, Acciente LLC
 *
 * Acciente LLC licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.acciente.oacc.sql;

import java.io.IOException;
import java.io.StringReader;
import java.util.Properties;

public class TestSQLAccessControlContextBase {
   private static final String PROP_DbUrl       = "-dburl";
   private static final String PROP_DbUser      = "-dbuser";
   private static final String PROP_DbPwd       = "-dbpwd";
   private static final String PROP_DbSchema    = "-dbschema";
   private static final String PROP_OACCRootPwd = "-oaccrootpass";

   protected static String dbUrl;
   protected static String dbUser;
   protected static String dbPwd;
   protected static String dbSchema;
   protected static char[] oaccRootPwd;

   protected static void testName(String testName) {
      System.out.print("Test: " + testName + "...");
   }

   protected static void testOK() {
      System.out.println("OK");
   }

   protected static void testOK(Exception e) {
      System.out.println("OK: " + e.getMessage());
   }

   protected static void testFail() {
      System.out.println("Failed < < < < < < < < <");
   }

   protected static void testFail(Exception e) {
      System.out.println("Failed: " + e.getClass().getName() + " - " + e.getMessage() + "  < < < < < < < < <");
   }

   protected static void setupName(String setupName) {
      System.out.print("Setup: " + setupName + "...");
   }

   protected static void setupOK() {
      System.out.println("OK");
   }

   protected static void setupFail() {
      System.out.println("Failed < < < < < < < < <");
   }

   protected static void setupFail(Exception e) {
      System.out.println("Failed: " + e.getMessage() + " < < < < < < < < <");
   }

   protected static boolean checkDBConnectArgs(String[] args) {
      if (args.length < 4) {
         System.out.println("Usage: java com.acciente.oacc.sql.TestSQLAccessControlContext "
                                  + PROP_DbUrl + "=<db-url> "
                                  + PROP_DbUser + "=<db-user> "
                                  + PROP_DbPwd + "=<db-password> "
                                  + PROP_OACCRootPwd + "=<OACC-root-password> "
                                  + " [" + PROP_DbSchema + "=<db-schema>]");
         return false;
      }

      return true;
   }

   protected static void readDBConnectArgs(String[] args)
         throws IOException {
      // first read the command line args into a properties object
      Properties initArgs = new Properties();

      for (int i = 0; i < args.length; i++) {
         initArgs.load(new StringReader(args[i]));
      }

      // get the parameters into local vars and assign defaults as needed
      dbUrl = initArgs.getProperty(PROP_DbUrl);
      dbUser = initArgs.getProperty(PROP_DbUser);
      dbPwd = initArgs.getProperty(PROP_DbPwd);
      dbSchema = initArgs.getProperty(PROP_DbSchema, "TEST_OACC");
      oaccRootPwd = initArgs.getProperty(PROP_OACCRootPwd).toCharArray();

      // check if we have all the required parameters
      if (dbUrl == null) {
         throw new IllegalArgumentException(PROP_DbUrl + " is required!");
      }
      if (dbUser == null) {
         throw new IllegalArgumentException(PROP_DbUser + " is required!");
      }
      if (dbPwd == null) {
         throw new IllegalArgumentException(PROP_DbPwd + " is required!");
      }
      if (oaccRootPwd == null) {
         throw new IllegalArgumentException(PROP_OACCRootPwd + " is required!");
      }
   }
}
