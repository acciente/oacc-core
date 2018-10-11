/*
 * Copyright 2009-2018, Acciente LLC
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

import com.acciente.oacc.encryptor.PasswordEncryptor;
import com.acciente.oacc.sql.internal.SQLAccessControlSystemInitializer;
import com.acciente.oacc.sql.internal.SchemaNameValidator;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class SQLAccessControlSystemResetUtil {
   public static void resetOACC(Connection connection,
                                String dbSchema,
                                char[] oaccRootPwd,
                                PasswordEncryptor passwordEncryptor)
         throws SQLException {
      deleteAllOACCData(connection, dbSchema);
      SQLAccessControlSystemInitializer.initializeOACC(connection, dbSchema, oaccRootPwd, passwordEncryptor, true);
   }

   public static void resetOACC(DataSource dataSource, String dbSchema, char[] oaccRootPwd,
                                PasswordEncryptor passwordEncryptor)
         throws SQLException {
      try (Connection connection = dataSource.getConnection()) {
         deleteAllOACCData(connection, dbSchema);
         SQLAccessControlSystemInitializer.initializeOACC(connection, dbSchema, oaccRootPwd, passwordEncryptor, true);
      }
   }

   public static void deleteAllOACCData(Connection connection,
                                        String dbSchema) throws SQLException {
      PreparedStatement statement = null;

      SchemaNameValidator.assertValid(dbSchema);

      try {
         final String schemaNameAndTablePrefix = dbSchema != null ? dbSchema + ".OAC_" : "OAC_";

         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_DomPerm_Sys");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_DomCrPerm_Sys");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_DomCrPerm_PostCr_Sys");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResPerm_Sys");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResPerm");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_Global_ResPerm_Sys");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_Global_ResPerm");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResCrPerm_Sys");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResCrPerm_PostCr_Sys");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Grant_ResCrPerm_PostCr");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "ResourcePassword");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "ResourceExternalID");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Resource");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "ResourceClassPermission");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "ResourceClass");
         statement.executeUpdate();
         statement.close();
         statement = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Domain");
         try {
            statement.executeUpdate();
            statement.close();
         }
         catch (SQLException e) {
            // some RDBMS don't support deletion of all rows from a table with a self-referential FK constraint,
            // so let's try to remove each domain's children first

            deleteDomainsIndividually(connection, schemaNameAndTablePrefix);
         }
      }
      finally {
         if (statement != null) {
            statement.close();
         }
      }
   }

   protected static void deleteDomainsIndividually(Connection connection,
                                                   String schemaNameAndTablePrefix) throws SQLException {
      // some RDBMS don't support deletion with a sub-select from the same table,
      // so let's break this down into an ultra-compatible algorithm:
      // delete individual childless rows, until no more rows are left
      try (PreparedStatement selectStatement
                 = connection.prepareStatement("SELECT DomainID FROM " + schemaNameAndTablePrefix + "Domain WHERE DomainID NOT IN ("
                                                     + "SELECT ParentDomainID FROM " + schemaNameAndTablePrefix
                                                     + "Domain WHERE ParentDomainID IS NOT NULL)");
           PreparedStatement deleteStatement
                 = connection.prepareStatement("DELETE FROM " + schemaNameAndTablePrefix + "Domain WHERE DomainID = ?")) {

         List<Integer> leafDomainIds;
         do {
            // first, find domains without children
            leafDomainIds = new ArrayList<>();
            ResultSet resultSet = selectStatement.executeQuery();

            while (resultSet.next()) {
               leafDomainIds.add(resultSet.getInt("DomainId"));
            }
            resultSet.close();

            // then delete those domains without children
            for (int leafDomainId : leafDomainIds) {
               deleteStatement.setInt(1, leafDomainId);
               deleteStatement.executeUpdate();
            }
         } while (!leafDomainIds.isEmpty());
      }
   }
}
