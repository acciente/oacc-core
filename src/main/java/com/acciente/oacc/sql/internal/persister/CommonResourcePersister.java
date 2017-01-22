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
import com.acciente.oacc.Resources;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.io.Serializable;
import java.sql.SQLException;

public abstract class CommonResourcePersister extends Persister implements ResourcePersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected static final String[] GENERATED_KEY_COLUMNS = new String[]{"ResourceId"};

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public CommonResourcePersister(SQLProfile sqlProfile,
                                  SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public void verifyResourceExists(SQLConnection connection,
                                    Resource resource) {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_ResourceId_BY_ResourceID);
         statement.setResourceId(1, resource);
         resultSet = statement.executeQuery();

         // complain if we do not find the resource
         if (!resultSet.next()) {
            throw new IllegalArgumentException("Resource " + resource + " not found!");
         }

         // complain if we found more than one resource!
         // (assuming the PK constraint is being enforced by the DB, currently do not see how this can happen)
         if (resultSet.next()) {
            throw new IllegalStateException("Resource reference " + resource + " maps to more than one resource!");
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public Resource createResource(SQLConnection connection,
                                  Id<ResourceClassId> resourceClassId,
                                  Id<DomainId> resourceDomainId,
                                  String externalId) {
      SQLStatement statement = null;

      try {
         final Id<ResourceId> nextResourceId;

         // pick the resource creation strategy based on if the database supports sequence generators
         if (sqlProfile.isSequenceEnabled()) {
            nextResourceId = getNextResourceId(connection);
            if (nextResourceId == null) {
               throw new IllegalStateException("could not retrieve next ResourceId from sequence");
            }

            statement = connection.prepareStatement(sqlStrings.SQL_createInResource_WITH_ResourceID_ResourceClassID_DomainID);
            statement.setResourceId(1, nextResourceId);
            statement.setResourceClassId(2, resourceClassId);
            statement.setResourceDomainId(3, resourceDomainId);

            assertOneRowInserted(statement.executeUpdate());
         }
         else {
            statement = connection.prepareStatement(sqlStrings.SQL_createInResource_WITH_ResourceClassID_DomainID,
                                                    GENERATED_KEY_COLUMNS);
            statement.setResourceClassId(1, resourceClassId);
            statement.setResourceDomainId(2, resourceDomainId);

            assertOneRowInserted(statement.executeUpdate());

            final SQLResult generatedKeys = statement.getGeneratedKeys();

            if (!generatedKeys.next()) {
               throw new IllegalStateException("could not retrieve auto-generated ResourceId");
            }

            nextResourceId = generatedKeys.getNextResourceId(1);

            if (nextResourceId == null) {
               throw new IllegalStateException("could not retrieve auto-generated ResourceId");
            }
            generatedKeys.close();
         }
         closeStatement(statement);

         // save the new resource's external id, if necessary, and return the new resource
         if (externalId != null) {
            return setExternalId(connection, nextResourceId, externalId);
         }
         else {
            return Resources.getInstance(nextResourceId.getValue());
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public Resource setExternalId(SQLConnection connection,
                                 Id<ResourceId> resourceId,
                                 String externalId) {
      SQLStatement statement = null;

      try {
         // save the new resource's external id and return the new resource reference
         statement = connection.prepareStatement(sqlStrings.SQL_createInResourceExternalId_WITH_ResourceID_ExternalID);
         statement.setResourceId(1, resourceId);
         statement.setString(2, externalId);

         assertOneRowInserted(statement.executeUpdate());

         return Resources.getInstance(resourceId.getValue(), externalId);
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void deleteResource(SQLConnection connection,
                              Resource resource) {
      SQLStatement statement = null;

      try {
         // delete the resource's external id mapping, if exists
         statement = connection.prepareStatement(sqlStrings.SQL_removeInResourceExternalId_BY_ResourceID);
         statement.setResourceId(1, resource);
         statement.executeUpdate();
         closeStatement(statement);

         // delete resource
         statement = connection.prepareStatement(sqlStrings.SQL_removeInResource_BY_ResourceID);
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

   @Override
   public Id<DomainId> getDomainIdByResource(SQLConnection connection,
                                             Resource resource) {
      SQLStatement statement = null;

      try {
         Id<DomainId> domainId = null;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_DomainID_BY_ResourceID);
         statement.setResourceId(1, resource);
         SQLResult resultSet = statement.executeQuery();

         if (resultSet.next()) {
            domainId = resultSet.getResourceDomainId("DomainId");
         }

         if (domainId == null) {
            throw new IllegalArgumentException("Could not determine domain for resource: " + resource);
         }

         return domainId;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public Id<ResourceId> getNextResourceId(SQLConnection connection) {
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
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public abstract boolean isDomainEmpty(SQLConnection connection, Id<DomainId> resourceDomainId);

   @Override
   public Resource resolveResourceByExternalId(SQLConnection connection,
                                               String externalId) {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResourceExternalId_ResourceId_ExternalId_BY_ExternalID);
         statement.setString(1, externalId);
         resultSet = statement.executeQuery();

         if (!resultSet.next()) {
            return null;
         }

         final Resource resolvedResourceId = resultSet.getResource("ResourceId", "ExternalId");

         // complain if we found more than one resource - external ids are supposed to be globally unique
         if (resultSet.next()) {
            throw new IllegalStateException("External id " + externalId + " maps to more than one resource!");
         }

         return resolvedResourceId;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public Resource resolveResourceByResourceId(SQLConnection connection,
                                               Resource resource) {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_ResourceId_ExternalId_BY_ResourceID);
         statement.setResourceId(1, resource);
         resultSet = statement.executeQuery();

         // complain if we do not find the resource
         if (!resultSet.next()) {
            return null;
         }

         Resource resolvedResource = resultSet.getResource("ResourceId", "ExternalId");

         // complain if we found more than one resource - external ids are supposed to be globally unique
         if (resultSet.next()) {
            throw new IllegalStateException("Resource " + resource + " maps to more than one resource!");
         }

         return resolvedResource;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }
}
