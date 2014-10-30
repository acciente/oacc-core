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
package com.acciente.oacc.sql.internal.persister;

import com.acciente.oacc.AccessControlException;
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.sql.SQLException;
import java.sql.Types;

public class ResourcePersister extends Persister {
   private final SQLStrings sqlStrings;

   public ResourcePersister(SQLStrings sqlStrings) {
      this.sqlStrings = sqlStrings;
   }

   public String getEncryptedBoundPasswordByResourceId(SQLConnection connection,
                                                       Resource resource) throws AccessControlException {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_Password_BY_ResourceID);
         statement.setResourceId(1, resource);
         resultSet = statement.executeQuery();

         // complain if we do not find the resource
         if (!resultSet.next()) {
            throw new AccessControlException(resource + " not found!");
         }

         // complain if the resource has no password set
         final String encryptedBoundPassword = resultSet.getString("Password");
         if (encryptedBoundPassword == null) {
            throw new AccessControlException(resource + " has no password set!");
         }

         // complain if we found more than one resource!
         // (assuming the PK constraint is being enforced by the DB, currently do not see how this can happen)
         if (resultSet.next()) {
            throw new AccessControlException(resource + " maps to more than one resource!");
         }
         return encryptedBoundPassword;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void verifyResourceExists(SQLConnection connection,
                                    Resource resource) throws AccessControlException {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_Password_BY_ResourceID);
         statement.setResourceId(1, resource);
         resultSet = statement.executeQuery();

         // complain if we do not find the resource
         if (!resultSet.next()) {
            throw new AccessControlException(resource + " not found!");
         }

         // complain if we found more than one resource!
         // (assuming the PK constraint is being enforced by the DB, currently do not see how this can happen)
         if (resultSet.next()) {
            throw new AccessControlException(resource + " maps to more than one resource!");
         }
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void updateEncryptedBoundPasswordByResourceId(SQLConnection connection,
                                                        Resource resource,
                                                        String newEncryptedBoundPassword) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_updateInResource_Password_BY_ResourceID);
         statement.setString(1, newEncryptedBoundPassword);
         statement.setResourceId(2, resource);
         assertOneRowUpdated(statement.executeUpdate());
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public int getResourceCount(SQLConnection connection,
                               Id<ResourceClassId> resourceClassId,
                               Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_COUNTResourceID_BY_ResourceClassID_DomainID);
         statement.setResourceClassId(1, resourceClassId);
         statement.setResourceDomainId(2, resourceDomainId);
         resultSet = statement.executeQuery();

         if (!resultSet.next()) {
            throw new AccessControlException("Could not read count, class: " + resourceClassId + " domain:" + resourceDomainId);
         }

         final int count = resultSet.getInteger("COUNTResourceID");

         resultSet.close();

         return count;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void createResource(SQLConnection connection,
                              Id<ResourceId> newResourceId,
                              Id<ResourceClassId> resourceClassId,
                              Id<DomainId> resourceDomainId,
                              String encryptedBoundPassword) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_createInResource_WITH_ResourceID_ResourceClassID_DomainID_Password);
         statement.setResourceId(1, newResourceId);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourceDomainId(3, resourceDomainId);

         if (encryptedBoundPassword == null) {
            statement.setNull(4, Types.VARCHAR);
         }
         else {
            statement.setString(4, encryptedBoundPassword);
         }

         assertOneRowInserted(statement.executeUpdate());
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Id<ResourceId> getNextResourceId(SQLConnection connection)
         throws AccessControlException {
      SQLStatement statement = null;
      Id<ResourceId> newResourceId = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlStrings.SQL_nextResourceID);
         resultSet = statement.executeQuery();

         if (resultSet.next()) {
            newResourceId = resultSet.getNextResourceId(1);
         }

         resultSet.close();

         return newResourceId;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }
}
