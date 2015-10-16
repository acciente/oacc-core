/*
 * Copyright 2009-2015, Acciente LLC
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
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public class SQLAccessControlSystemInitializer {
   private static final String PROP_DbUrl       = "-dburl";
   private static final String PROP_DbUser      = "-dbuser";
   private static final String PROP_DbPwd       = "-dbpwd";
   private static final String PROP_DbSchema    = "-dbschema";
   private static final String PROP_OACCRootPwd = "-oaccsystempwd";

   public static void main(String args[]) throws SQLException, IOException {
      if (args.length == 0) {
         System.out.println("Usage: java com.acciente.oacc.sql.SQLAccessControlSystemInitializer"
                                  + PROP_DbUrl + "=<db-url> "
                                  + PROP_DbUser + "=<db-user> "
                                  + PROP_DbPwd + "=<db-password> "
                                  + PROP_OACCRootPwd + "=<OACC-system-password> "
                                  + " [ " + PROP_DbSchema + "=<db-schema>]");
         return;
      }

      // first read the command line args into a properties object
      Properties initArgs = new Properties();

      for (int i = 0; i < args.length; i++) {
         initArgs.load(new StringReader(args[i]));
      }

      String dbUrl;
      String dbUser;
      String dbPwd;
      String dbSchema;
      String oaccRootPwd;

      // get the parameters into local vars and assign defaults as needed
      dbUrl = initArgs.getProperty(PROP_DbUrl);
      dbUser = initArgs.getProperty(PROP_DbUser);
      dbPwd = initArgs.getProperty(PROP_DbPwd);
      dbSchema = initArgs.getProperty(PROP_DbSchema, "TEST_OACC");
      oaccRootPwd = initArgs.getProperty(PROP_OACCRootPwd);

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

      initializeOACC(dbUrl, dbUser, dbPwd, dbSchema, oaccRootPwd.toCharArray());
   }

   public static void initializeOACC(String dbUrl,
                                     String dbUser,
                                     String dbPwd,
                                     String dbSchema,
                                     char[] oaccRootPwd) throws SQLException {
      System.out.println("Connecting to OACC database @ " + dbUrl);
      Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPwd);

      try {
         // delegate to internal handler
         com.acciente.oacc.sql.internal.SQLAccessControlSystemInitializer.initializeOACC(connection,
                                                                                         dbSchema,
                                                                                         oaccRootPwd);
      }
      finally {
         System.out.println("Disconnecting from OACC database @ " + dbUrl);
         connection.close();
      }

      System.out.println("Initialize..OK!");
   }

   public static void initializeOACC(Connection connection,
                                     String dbSchema,
                                     char[] oaccRootPwd) throws SQLException {
      // delegate to internal handler
      com.acciente.oacc.sql.internal.SQLAccessControlSystemInitializer.initializeOACC(connection,
                                                                                      dbSchema,
                                                                                      oaccRootPwd);
   }
}
