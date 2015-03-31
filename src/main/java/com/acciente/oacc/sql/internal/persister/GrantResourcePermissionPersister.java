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
package com.acciente.oacc.sql.internal.persister;

import com.acciente.oacc.Resource;
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourcePermissionId;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class GrantResourcePermissionPersister extends Persister {
   private final SQLStrings sqlStrings;

   public GrantResourcePermissionPersister(SQLStrings sqlStrings) {
      this.sqlStrings = sqlStrings;
   }

   public Set<Resource> getResourcesByResourcePermission(SQLConnection connection,
                                                         Resource accessorResource,
                                                         Id<ResourceClassId> resourceClassId,
                                                         ResourcePermission resourcePermission,
                                                         Id<ResourcePermissionId> resourcePermissionId) {
      if (resourcePermission.isSystemPermission()) {
         throw new IllegalArgumentException("Permission: " + resourcePermission + " is not a non-system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via direct permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermission_ResourceID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant);
         statement.setResourceId(1, accessorResource);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourcePermissionId(3, resourcePermissionId);
         statement.setBoolean(4, resourcePermission.isWithGrant());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId"));
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

   public Set<Resource> getResourcesByResourcePermission(SQLConnection connection,
                                                         Resource accessorResource,
                                                         Id<ResourceClassId> resourceClassId,
                                                         Id<DomainId> resourceDomainId,
                                                         ResourcePermission resourcePermission,
                                                         Id<ResourcePermissionId> resourcePermissionId) {
      if (resourcePermission.isSystemPermission()) {
         throw new IllegalArgumentException("Permission: " + resourcePermission + " is not a non-system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via direct permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermission_ResourceID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         statement.setResourcePermissionId(4, resourcePermissionId);
         statement.setBoolean(5, resourcePermission.isWithGrant());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId"));
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

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermission_ResourceID_BY_AccessedID_ResourceClassID_PermissionID_IsWithGrant);
         statement.setResourceId(1, accessedResource);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourcePermissionId(3, resourcePermissionId);
         statement.setBoolean(4, resourcePermission.isWithGrant());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId"));
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

   public Set<ResourcePermission> getResourcePermissionsIncludeInherited(SQLConnection connection,
                                                                         Resource accessorResource,
                                                                         Resource accessedResource) {
      SQLStatement statement = null;
      try {
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermission_ResourceClassName_PermissionName_IsWithGrant_InheritLevel_BY_AccessorID_AccessedID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceId(2, accessedResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(ResourcePermissions.getInstance(
                  resultSet.getString("PermissionName"),
                  resultSet.getBoolean("IsWithGrant"),
                  resultSet.getInteger("InheritLevel"),
                  0 /* zero since domain level does not apply in context of direct permissions */));
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
            resourcePermissions.add(ResourcePermissions.getInstance(
                  resultSet.getString("PermissionName"),
                  resultSet.getBoolean("IsWithGrant"),
                  0, // inherit level does not apply to direct permissions
                  0 /* zero since domain level does not apply in context of direct permissions */));
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
               statement.setBoolean(4, resourcePermission.isWithGrant());
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
               statement.setBoolean(2, resourcePermission.isWithGrant());
               statement.setResourceId(3, accessorResource);
               statement.setResourceId(4, accessedResource);
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setResourceClassId(6, accessedResourceClassId);
               statement.setString(7, resourcePermission.getPermissionName());

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
}
