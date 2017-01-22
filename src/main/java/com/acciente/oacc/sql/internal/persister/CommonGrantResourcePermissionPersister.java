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
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourcePermissionId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public abstract class CommonGrantResourcePermissionPersister extends Persister implements GrantResourcePermissionPersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public CommonGrantResourcePermissionPersister(SQLProfile sqlProfile,
                                                 SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public abstract Set<Resource> getResourcesByResourcePermission(SQLConnection connection,
                                                                  Resource accessorResource,
                                                                  Id<ResourceClassId> resourceClassId,
                                                                  ResourcePermission resourcePermission,
                                                                  Id<ResourcePermissionId> resourcePermissionId);

   @Override
   public abstract Set<Resource> getResourcesByResourcePermission(SQLConnection connection,
                                                                  Resource accessorResource,
                                                                  Id<ResourceClassId> resourceClassId,
                                                                  Id<DomainId> resourceDomainId,
                                                                  ResourcePermission resourcePermission,
                                                                  Id<ResourcePermissionId> resourcePermissionId);

   @Override
   public Set<Resource> getAccessorResourcesByResourcePermission(SQLConnection connection,
                                                                 Resource accessedResource,
                                                                 Id<ResourceClassId> resourceClassId,
                                                                 ResourcePermission resourcePermission,
                                                                 Id<ResourcePermissionId> resourcePermissionId) {
      if (resourcePermission.isSystemPermission()) {
         throw new IllegalArgumentException("Permission: " + resourcePermission + " is not a non-system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of resources of the specified type that direct permissions to the specified accessed resource
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermission_ResourceID_ExternalID_BY_AccessedID_ResourceClassID_PermissionID_IsWithGrant);
         statement.setResourceId(1, accessedResource);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourcePermissionId(3, resourcePermissionId);
         statement.setBoolean(4, resourcePermission.isWithGrantOption());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId", "ExternalId"));
         }
         resultSet.close();

         return resources;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public abstract Set<ResourcePermission> getResourcePermissionsIncludeInherited(SQLConnection connection,
                                                                                  Resource accessorResource,
                                                                                  Resource accessedResource);

   @Override
   public Set<ResourcePermission> getResourcePermissions(SQLConnection connection,
                                                         Resource accessorResource,
                                                         Resource accessedResource) {
      SQLStatement statement = null;
      try {
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermission_withoutInheritance_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID_AccessedID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceId(2, accessedResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(getResourcePermission(resultSet));
         }
         resultSet.close();

         return resourcePermissions;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   protected static ResourcePermission getResourcePermission(SQLResult resultSet) throws SQLException {
      final String permissionName = resultSet.getString("PermissionName");

      if (resultSet.getBoolean("IsWithGrant")) {
         return ResourcePermissions.getInstanceWithGrantOption(permissionName);
      }
      else {
         return ResourcePermissions.getInstance(permissionName);
      }
   }

   @Override
   public void addResourcePermissions(SQLConnection connection,
                                      Resource accessorResource,
                                      Resource accessedResource,
                                      Id<ResourceClassId> accessedResourceClassId,
                                      Set<ResourcePermission> requestedResourcePermissions,
                                      Resource grantorResource) {
      SQLStatement statement = null;
      try {
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantResourcePermission_WITH_AccessorID_GrantorID_AccessedID_IsWithGrant_ResourceClassID_PermissionName);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (!resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setResourceId(3, accessedResource);
               statement.setBoolean(4, resourcePermission.isWithGrantOption());
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setString(6, resourcePermission.getPermissionName());

               assertOneRowInserted(statement.executeUpdate());
            }
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
   public void updateResourcePermissions(SQLConnection connection,
                                         Resource accessorResource,
                                         Resource accessedResource,
                                         Id<ResourceClassId> accessedResourceClassId,
                                         Set<ResourcePermission> requestedResourcePermissions,
                                         Resource grantorResource) {
      SQLStatement statement = null;
      try {
         statement = connection.prepareStatement(sqlStrings.SQL_updateInGrantResourcePermission_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedID_ResourceClassID_PermissionName);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (!resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, grantorResource);
               statement.setBoolean(2, resourcePermission.isWithGrantOption());
               statement.setResourceId(3, accessorResource);
               statement.setResourceId(4, accessedResource);
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setString(6, resourcePermission.getPermissionName());

               assertOneRowUpdated(statement.executeUpdate());
            }
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
   public void removeAllResourcePermissionsAsAccessorOrAccessed(SQLConnection connection,
                                                                Resource resource) {
      SQLStatement statement = null;
      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourcePermission_BY_AccessorID_OR_AccessedID);
         statement.setResourceId(1, resource);
         statement.setResourceId(2, resource);
         statement.executeUpdate();
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void removeResourcePermissions(SQLConnection connection,
                                         Resource accessorResource,
                                         Resource accessedResource) {
      SQLStatement statement = null;
      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourcePermission_BY_AccessorID_AccessedID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceId(2, accessedResource);
         statement.executeUpdate();
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void removeResourcePermissions(SQLConnection connection,
                                         Resource accessorResource,
                                         Resource accessedResource,
                                         Id<ResourceClassId> accessedResourceClassId,
                                         Set<ResourcePermission> requestedResourcePermissions) {
      SQLStatement statement = null;
      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourcePermission_BY_AccessorID_AccessedID_ResourceClassID_PermissionName);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (!resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, accessedResource);
               statement.setResourceClassId(3, accessedResourceClassId);
               statement.setString(4, resourcePermission.getPermissionName());

               assertOneRowUpdated(statement.executeUpdate());
            }
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }
}
