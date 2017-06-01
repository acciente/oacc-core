/*
 * Copyright 2009-2017, Acciente LLC
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

import com.acciente.oacc.encryptor.PasswordEncryptor;
import com.acciente.oacc.sql.internal.encryptor.PasswordEncryptors;

import java.io.IOException;
import java.io.StringReader;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.List;
import java.util.Properties;

public class SQLAccessControlSystemInitializer {
   private static final String PROP_DbUrl        = "-dburl";
   private static final String PROP_DbUser       = "-dbuser";
   private static final String PROP_DbPwd        = "-dbpwd";
   private static final String PROP_DbSchema     = "-dbschema";
   private static final String PROP_PwdEncryptor = "-pwdencryptor";
   private static final String PROP_OACCRootPwd  = "-oaccsystempwd";
   private static final String OPT_HELP_SHORT    = "-h";
   private static final String OPT_HELP_LONG     = "--help";
   private static final String OPT_HELP_QUESTION = "-?";
   private static final String USAGE = "Usage:" +
         "\n  java com.acciente.oacc.SQLAccessControlSystemInitializer " +
         PROP_DbUrl + "=<db-url> " +
         PROP_PwdEncryptor + "=(" +
         join(" | ", PasswordEncryptors.getSupportedEncryptorNames()) + ") " +
         PROP_OACCRootPwd + "=<OACC-system-password> " +
         "[options]" +
         "\n\nOptions:" +
         "\n  " + PROP_DbUser + "=<db-user>      Database username." +
         "\n  " + PROP_DbPwd + "=<db-password>   Database password." +
         "\n  " + PROP_DbSchema + "=<db-schema>  Database schema." +
         "\n\nOther:" +
         "\n  -h, --help, -?         Shows usage info.";

   public static void main(String args[]) throws SQLException, IOException {
      // first read the command line args into a properties object
      Properties optionArgs = new Properties();

      for (String arg : args) {
         optionArgs.load(new StringReader(arg));
      }

      // print usage info, if necessary
      if (args.length == 0
            || optionArgs.containsKey(OPT_HELP_SHORT)
            || optionArgs.containsKey(OPT_HELP_LONG)
            || optionArgs.containsKey(OPT_HELP_QUESTION)) {
         System.out.println(USAGE);
         return;
      }

      verifyOptionArgs(optionArgs);

      initializeOACC(optionArgs.getProperty(PROP_DbUrl),
                     optionArgs.getProperty(PROP_DbUser),
                     optionArgs.getProperty(PROP_DbPwd),
                     optionArgs.getProperty(PROP_DbSchema),
                     optionArgs.getProperty(PROP_OACCRootPwd).toCharArray(),
                     PasswordEncryptors.getPasswordEncryptor(optionArgs.getProperty(PROP_PwdEncryptor)));
   }

   private static void verifyOptionArgs(Properties optionArgs) {
      if (optionArgs.getProperty(PROP_DbUrl) == null) {
         throw new IllegalArgumentException(PROP_DbUrl + " is required!\n" + USAGE);
      }
      if (optionArgs.getProperty(PROP_PwdEncryptor) == null) {
         throw new IllegalArgumentException(PROP_PwdEncryptor + " is required!\n" + USAGE);
      }
      if (optionArgs.getProperty(PROP_OACCRootPwd) == null) {
         throw new IllegalArgumentException(PROP_OACCRootPwd + " is required!\n" + USAGE);
      }
   }

   public static void initializeOACC(String dbUrl,
                                     String dbUser,
                                     String dbPwd,
                                     String dbSchema,
                                     char[] oaccRootPwd,
                                     PasswordEncryptor passwordEncryptor) throws SQLException {
      System.out.println("Connecting to OACC database @ " + dbUrl);

      try (Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPwd)) {
         // delegate to internal handler
         com.acciente.oacc.sql.internal.SQLAccessControlSystemInitializer.initializeOACC(connection,
                                                                                         dbSchema,
                                                                                         oaccRootPwd,
                                                                                         passwordEncryptor);
      }
      finally {
         System.out.println("Disconnecting from OACC database @ " + dbUrl);
      }

      System.out.println("Initialize..OK!");
   }

   public static void initializeOACC(Connection connection,
                                     String dbSchema,
                                     char[] oaccRootPwd,
                                     PasswordEncryptor passwordEncryptor) throws SQLException {
      // delegate to internal handler
      com.acciente.oacc.sql.internal.SQLAccessControlSystemInitializer.initializeOACC(connection,
                                                                                      dbSchema,
                                                                                      oaccRootPwd,
                                                                                      passwordEncryptor);
   }

   //TODO remove this method and replace its usages with String.join() when OACC updates to Java 8
   /**
    * Provides identical functionality of the Strings.join() method in Java 8
    *
    * @param delimiter the delimiter to insert between elements
    * @param elements the elements to concatenate
    * @return a String of the specified elements joined by the specified delimiter
    */
   private static String join(final String delimiter, final List<String> elements) {
      if (elements == null || elements.size() == 0) {
         return "";
      }

      final StringBuilder result = new StringBuilder(elements.get(0));
      for (String element : elements.subList(1, elements.size())) {
         result.append(delimiter);
         result.append(element);
      }
      return result.toString();
   }
}
