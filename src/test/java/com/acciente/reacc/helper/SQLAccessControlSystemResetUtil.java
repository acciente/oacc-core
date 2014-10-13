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
package com.acciente.reacc.helper;

import com.acciente.reacc.sql.internal.SQLAccessControlSystemInitializer;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class SQLAccessControlSystemResetUtil {
   public static void resetREACC(Connection connection, String dbSchema, String reaccRootPwd)
         throws SQLException, InterruptedException {
      deleteAllREACCData(connection, dbSchema);
      SQLAccessControlSystemInitializer.initializeREACC(connection, dbSchema, reaccRootPwd);
   }

   public static void resetREACC(DataSource dataSource, String dbSchema, String reaccRootPwd)
         throws SQLException, InterruptedException {
      try (Connection connection = dataSource.getConnection()) {
         deleteAllREACCData(connection, dbSchema);
         SQLAccessControlSystemInitializer.initializeREACC(connection, dbSchema, reaccRootPwd);
      }
   }

   public static void deleteAllREACCData(Connection connection,
                                         String dbSchema) throws SQLException, InterruptedException {
      PreparedStatement statement;

      final String schemaNameAndTablePrefix = dbSchema != null ? dbSchema + ".RAC_" : "RAC_";

      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_DomPerm_Sys");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_DomCrPerm_Sys");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_DomCrPerm_PostCr_Sys");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResPerm_Sys");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResPerm");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_Global_ResPerm_Sys");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_Global_ResPerm");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResCrPerm_Sys");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResCrPerm_PostCr_Sys");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResCrPerm_PostCr");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Resource");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "ResourceClassPermission");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "ResourceClass");
      statement.executeUpdate();
      statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Domain");
      statement.executeUpdate();
   }
}
