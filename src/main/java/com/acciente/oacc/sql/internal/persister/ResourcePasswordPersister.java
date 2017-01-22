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
package com.acciente.oacc.sql.internal.persister;

import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.io.Serializable;
import java.sql.SQLException;

public class ResourcePasswordPersister extends Persister implements Serializable {
   private static final long serialVersionUID = 1L;

   private final SQLPasswordStrings sqlPasswordStrings;

   public ResourcePasswordPersister(SQLPasswordStrings sqlPasswordStrings) {
      this.sqlPasswordStrings = sqlPasswordStrings;
   }

   public String getEncryptedBoundPasswordByResourceId(SQLConnection connection,
                                                       Resource resource) {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlPasswordStrings.SQL_findInResourcePassword_Password_BY_ResourceID);
         statement.setResourceId(1, resource);
         resultSet = statement.executeQuery();

         // complain if we do not find the resource
         if (!resultSet.next()) {
            throw new IllegalArgumentException(resource + " not found!");
         }

         // complain if the resource has no password set
         final String encryptedBoundPassword = resultSet.getString("Password");
         if (encryptedBoundPassword == null) {
            throw new IllegalStateException(resource + " has no password set!");
         }

         // complain if we found more than one resource!
         // (assuming the PK constraint is being enforced by the DB, currently do not see how this can happen)
         if (resultSet.next()) {
            throw new IllegalStateException(resource + " maps to more than one resource!");
         }
         return encryptedBoundPassword;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void setEncryptedBoundPasswordByResourceId(SQLConnection connection,
                                                     Resource resource,
                                                     String newEncryptedBoundPassword) {
      __setEncryptedBoundPasswordByResourceId(connection, Id.<ResourceId>from(resource.getId()), newEncryptedBoundPassword);
   }

   public void setEncryptedBoundPasswordByResourceId(SQLConnection connection,
                                                     Id<ResourceId> resourceId,
                                                     String newEncryptedBoundPassword) {
      __setEncryptedBoundPasswordByResourceId(connection, resourceId, newEncryptedBoundPassword);
   }

   private void __setEncryptedBoundPasswordByResourceId(SQLConnection connection,
                                                        Id<ResourceId> resourceId,
                                                        String newEncryptedBoundPassword) {
      SQLStatement finderStatement = null;
      SQLStatement insertStatement = null;
      SQLStatement updateStatement = null;

      try {
         SQLResult resultSet;

         finderStatement = connection.prepareStatement(sqlPasswordStrings.SQL_findInResourcePassword_Password_BY_ResourceID);
         finderStatement.setResourceId(1, resourceId);
         resultSet = finderStatement.executeQuery();

         if (!resultSet.next()) {
            // insert new row
            insertStatement = connection.prepareStatement(sqlPasswordStrings.SQL_createInResourcePassword_WITH_ResourceID_Password);
            insertStatement.setResourceId(1, resourceId);
            insertStatement.setString(2, newEncryptedBoundPassword);

            assertOneRowInserted(insertStatement.executeUpdate());
         }
         else {
            // complain if we found more than one resource!
            if (resultSet.next()) {
               throw new IllegalStateException("ResourceId " + resourceId + " maps to more than one resource!");
            }

            // update existing row
            updateStatement = connection.prepareStatement(sqlPasswordStrings.SQL_updateInResourcePassword_Password_BY_ResourceID);
            updateStatement.setString(1, newEncryptedBoundPassword);
            updateStatement.setResourceId(2, resourceId);

            assertOneRowUpdated(updateStatement.executeUpdate());
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(finderStatement);
         closeStatement(insertStatement);
         closeStatement(updateStatement);
      }
   }

   public void removeEncryptedBoundPasswordByResourceId(SQLConnection connection, Resource resource) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlPasswordStrings.SQL_removeInResourcePassword_BY_ResourceID);
         statement.setResourceId(1, resource);

         assertOneRowUpdated(statement.executeUpdate());
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

}
