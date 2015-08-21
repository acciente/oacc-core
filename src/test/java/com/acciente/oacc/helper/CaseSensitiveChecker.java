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
package com.acciente.oacc.helper;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class CaseSensitiveChecker {
   private static final String SENTINEL_VALUE__lower  = "test_domain_case_sensitivity";
   private static final String SENTINEL_VALUE__UPPER  = SENTINEL_VALUE__lower.toUpperCase();
   private static final String INSERT_SENTINEL_VALUE  = "INSERT INTO "
         + DbBase.getSchemaAndTableNamePrefix(TestConfigLoader.getDatabaseSchema())
         + "Domain (DomainID, DomainName) VALUES (?, ?)";
   private static final String SELECT_SENTINEL_VALUES = "SELECT DomainID, DomainName FROM "
         + DbBase.getSchemaAndTableNamePrefix(TestConfigLoader.getDatabaseSchema())
         + "Domain WHERE DomainName = ?";
   private static final String DELETE_SENTINEL_VALUES = "DELETE FROM "
         + DbBase.getSchemaAndTableNamePrefix(TestConfigLoader.getDatabaseSchema())
         + "Domain WHERE DomainName = ? OR DomainName = ?";

   public static boolean isDatabaseCaseSensitive(DataSource dataSource) throws SQLException {
      boolean isSensitive = true;
      boolean hasSentinels = false;

      try (Connection connection = dataSource.getConnection();
           PreparedStatement deleteSentinelsStmt = connection.prepareStatement(DELETE_SENTINEL_VALUES);
           PreparedStatement insertSentinelStmt = connection.prepareStatement(INSERT_SENTINEL_VALUE);
           PreparedStatement selectSentinelsStmt = connection.prepareStatement(SELECT_SENTINEL_VALUES);) {
         deleteSentinelsStmt.setString(1, SENTINEL_VALUE__lower);
         deleteSentinelsStmt.setString(2, SENTINEL_VALUE__UPPER);
         deleteSentinelsStmt.executeUpdate();

         insertSentinelStmt.setInt(1, -999);
         insertSentinelStmt.setString(2, SENTINEL_VALUE__lower);
         insertSentinelStmt.executeUpdate();
         hasSentinels = true;

         insertSentinelStmt.setInt(1, -998);
         insertSentinelStmt.setString(2, SENTINEL_VALUE__UPPER);
         insertSentinelStmt.executeUpdate();

         selectSentinelsStmt.setString(1, SENTINEL_VALUE__lower);
         final ResultSet resultSet = selectSentinelsStmt.executeQuery();
         resultSet.next();
         isSensitive = ! resultSet.next();
         System.out.println("Database is " + (isSensitive ? "case sensitive" : "not case sensitive") );
      }
      finally {
         if (hasSentinels) {
            try (Connection connection = dataSource.getConnection();
                 PreparedStatement deleteSentinelsStmt = connection.prepareStatement(DELETE_SENTINEL_VALUES);) {
               deleteSentinelsStmt.setString(1, SENTINEL_VALUE__lower);
               deleteSentinelsStmt.setString(2, SENTINEL_VALUE__UPPER);
               deleteSentinelsStmt.executeUpdate();
            }
         }
      }

      return isSensitive;
   }
}
