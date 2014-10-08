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
package com.acciente.rsf.sql.internal.persister;

import com.acciente.rsf.AccessControlException;
import com.acciente.rsf.Resource;
import com.acciente.rsf.ResourcePermission;
import com.acciente.rsf.sql.internal.persister.id.DomainId;
import com.acciente.rsf.sql.internal.persister.id.Id;
import com.acciente.rsf.sql.internal.persister.id.ResourceClassId;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class GrantResourcePermissionSysPersister extends Persister {
   private final SQLStrings sqlStrings;

   public GrantResourcePermissionSysPersister(SQLStrings sqlStrings) {
      this.sqlStrings = sqlStrings;
   }

   public Set<Resource> getResourcesBySysPermission(SQLConnection connection,
                                                    Resource accessorResource,
                                                    Id<ResourceClassId> resourceClassId,
                                                    ResourcePermission resourcePermission) throws AccessControlException {
      if (!resourcePermission.isSystemPermission()) {
         throw new AccessControlException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via direct permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant);
         statement.setResourceId(1, accessorResource);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourceSystemPermissionId(3, resourcePermission.getSystemPermissionId());
         statement.setBoolean(4, resourcePermission.isWithGrant());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId"));
         }
         resultSet.close();

         return resources;

      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Set<Resource> getResourcesBySysPermission(SQLConnection connection,
                                                    Resource accessorResource,
                                                    Id<ResourceClassId> resourceClassId,
                                                    Id<DomainId> resourceDomainId,
                                                    ResourcePermission resourcePermission) throws AccessControlException {
      if (!resourcePermission.isSystemPermission()) {
         throw new AccessControlException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via direct permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         statement.setResourceSystemPermissionId(4, resourcePermission.getSystemPermissionId());
         statement.setBoolean(5, resourcePermission.isWithGrant());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId"));
         }
         resultSet.close();

         return resources;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Set<Resource> getAccessorResourcesBySysPermission(SQLConnection connection,
                                                            Resource accessedResource,
                                                            Id<ResourceClassId> resourceClassId,
                                                            ResourcePermission resourcePermission) throws AccessControlException {

      if (!resourcePermission.isSystemPermission()) {
         throw new AccessControlException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of resources of the specified type that direct permissions to the specified accessed resource
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_ResourceID_BY_AccessedID_ResourceClassID_SysPermissionID_IsWithGrant);
         statement.setResourceId(1, accessedResource);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourceSystemPermissionId(3, resourcePermission.getSystemPermissionId());
         statement.setBoolean(4, resourcePermission.isWithGrant());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId"));
         }
         resultSet.close();

         return resources;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Set<ResourcePermission> getSysPermissions(SQLConnection connection,
                                                    Resource accessorResource,
                                                    Resource accessedResource)
         throws AccessControlException {

      SQLStatement statement = null;
      try {
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         // collect the system permissions that the accessor this resource has to the accessor resource
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_ResourceClassName_SysPermissionID_IsWithGrant_InheritLevel_BY_AccessorID_AccessedID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceId(2, accessedResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(ResourcePermission.getInstance(resultSet.getResourceSysPermissionName("SysPermissionId"),
                                                                   resultSet.getBoolean("IsWithGrant"),
                                                                   resultSet.getInteger("InheritLevel"),
                                                                   0 /* zero since domain level does not apply in context of direct permissions */));
         }
         resultSet.close();

         return resourcePermissions;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void addSysPermissions(SQLConnection connection,
                                 Resource accessorResource,
                                 Resource accessedResource,
                                 Id<ResourceClassId> accessedResourceClassId,
                                 Set<ResourcePermission> requestedResourcePermissions,
                                 Resource grantorResource) throws AccessControlException {

      SQLStatement statement = null;
      try {
         // add the new system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedID_IsWithGrant_ResourceClassID_SysPermissionID);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setResourceId(3, accessedResource);
               statement.setBoolean(4, resourcePermission.isWithGrant());
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setResourceSystemPermissionId(6, resourcePermission.getSystemPermissionId());

               assertOneRowInserted(statement.executeUpdate());
            }
         }
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void removeSysPermissions(SQLConnection connection,
                                    Resource accessorResource,
                                    Resource accessedResource) throws AccessControlException {

      SQLStatement statement = null;
      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourcePermissionSys_BY_AccessorID_AccessedID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceId(2, accessedResource);
         statement.executeUpdate();
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }
}
