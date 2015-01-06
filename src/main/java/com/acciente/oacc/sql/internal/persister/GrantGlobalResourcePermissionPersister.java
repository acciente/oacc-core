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
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourcePermissionId;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class GrantGlobalResourcePermissionPersister extends Persister {
   private final SQLStrings sqlStrings;

   public GrantGlobalResourcePermissionPersister(SQLStrings sqlStrings) {
      this.sqlStrings = sqlStrings;
   }

   public Set<Resource> getResourcesByGlobalResourcePermission(SQLConnection connection,
                                                               Resource accessorResource,
                                                               Id<ResourceClassId> resourceClassId,
                                                               ResourcePermission resourcePermission,
                                                               Id<ResourcePermissionId> resourcePermissionId) throws AccessControlException {
      if (resourcePermission.isSystemPermission()) {
         throw new AccessControlException("Permission: " + resourcePermission + " is not a non-system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via global permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermission_ResourceID_BY_AccessorID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourcePermissionId(3, resourcePermissionId);
         statement.setBoolean(4, resourcePermission.isWithGrant());
         statement.setResourceClassId(5, resourceClassId);
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

   public Set<Resource> getResourcesByGlobalResourcePermission(SQLConnection connection,
                                                               Resource accessorResource,
                                                               Id<ResourceClassId> resourceClassId,
                                                               Id<DomainId> resourceDomainId,
                                                               ResourcePermission resourcePermission,
                                                               Id<ResourcePermissionId> resourcePermissionId) throws AccessControlException {
      if (resourcePermission.isSystemPermission()) {
         throw new AccessControlException("Permission: " + resourcePermission + " is not a non-system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via global permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermission_ResourceID_BY_AccessorID_DomainID_ResourceClassID_PermissionID_IsWithGrant_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         statement.setResourcePermissionId(4, resourcePermissionId);
         statement.setBoolean(5, resourcePermission.isWithGrant());
         statement.setResourceClassId(6, resourceClassId);
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

   public Set<ResourcePermission> getGlobalResourcePermissionsIncludeInherited(SQLConnection connection,
                                                                               Resource accessorResource,
                                                                               Id<ResourceClassId> resourceClassId,
                                                                               Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has to the accessed resource
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermission_PermissionName_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(ResourcePermissions.getInstance(
                  resultSet.getString("PermissionName"),
                  resultSet.getBoolean("IsWithGrant"),
                  resultSet.getInteger("InheritLevel"),
                  resultSet.getInteger("DomainLevel")));
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

   public Set<ResourcePermission> getGlobalResourcePermissions(SQLConnection connection,
                                                               Resource accessorResource,
                                                               Id<ResourceClassId> resourceClassId,
                                                               Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has to the accessed resource directly
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermission_withoutInheritance_PermissionName_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(ResourcePermissions.getInstance(
                  resultSet.getString("PermissionName"),
                  resultSet.getBoolean("IsWithGrant"),
                  0,
                  0));
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

   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalResourcePermissionsIncludeInherited(SQLConnection connection,
                                                                                                         Resource accessorResource)
         throws AccessControlException {
      SQLStatement statement = null;
      try {
         // collect the non-system permissions that the accessor has
         SQLResult resultSet;
         final Map<String, Map<String, Set<ResourcePermission>>> globalPermissionsMap = new HashMap<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermission_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            final String resourceDomainName;
            final String resourceClassName;
            Map<String, Set<ResourcePermission>> permissionsForResourceDomain;
            Set<ResourcePermission> resourcePermissionsForResourceClass;

            resourceDomainName = resultSet.getString("DomainName");
            resourceClassName = resultSet.getString("ResourceClassName");

            if ((permissionsForResourceDomain = globalPermissionsMap.get(resourceDomainName)) == null) {
               globalPermissionsMap.put(resourceDomainName,
                                        permissionsForResourceDomain = new HashMap<>());
            }

            if ((resourcePermissionsForResourceClass = permissionsForResourceDomain.get(resourceClassName)) == null) {
               permissionsForResourceDomain.put(resourceClassName,
                                                resourcePermissionsForResourceClass = new HashSet<>());
            }

            resourcePermissionsForResourceClass.add(ResourcePermissions.getInstance(
                  resultSet.getString("PermissionName"),
                  resultSet.getBoolean("IsWithGrant"),
                  resultSet.getInteger("InheritLevel"),
                  resultSet.getInteger("DomainLevel")));
         }
         resultSet.close();

         return globalPermissionsMap;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalResourcePermissions(SQLConnection connection,
                                                                                         Resource accessorResource)
         throws AccessControlException {
      SQLStatement statement = null;
      try {
         // collect the non-system permissions that the accessor has
         SQLResult resultSet;
         final Map<String, Map<String, Set<ResourcePermission>>> globalPermissionsMap = new HashMap<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermission_withoutInheritance_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            final String resourceDomainName;
            final String resourceClassName;
            Map<String, Set<ResourcePermission>> permissionsForResourceDomain;
            Set<ResourcePermission> resourcePermissionsForResourceClass;

            resourceDomainName = resultSet.getString("DomainName");
            resourceClassName = resultSet.getString("ResourceClassName");

            if ((permissionsForResourceDomain = globalPermissionsMap.get(resourceDomainName)) == null) {
               globalPermissionsMap.put(resourceDomainName,
                                        permissionsForResourceDomain = new HashMap<>());
            }

            if ((resourcePermissionsForResourceClass = permissionsForResourceDomain.get(resourceClassName)) == null) {
               permissionsForResourceDomain.put(resourceClassName,
                                                resourcePermissionsForResourceClass = new HashSet<>());
            }

            resourcePermissionsForResourceClass.add(ResourcePermissions.getInstance(
                  resultSet.getString("PermissionName"),
                  resultSet.getBoolean("IsWithGrant"),
                  0,
                  0));
         }
         resultSet.close();

         return globalPermissionsMap;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void addGlobalResourcePermissions(SQLConnection connection,
                                            Resource accessorResource,
                                            Id<ResourceClassId> accessedResourceClassId,
                                            Id<DomainId> accessedResourceDomainId,
                                            Set<ResourcePermission> requestedResourcePermissions,
                                            Resource grantorResource) throws AccessControlException {
      SQLStatement statement = null;
      try {
         // add the new non-system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantGlobalResourcePermission_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_PermissionName);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (!resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setResourceDomainId(3, accessedResourceDomainId);
               statement.setBoolean(4, resourcePermission.isWithGrant());
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setString(6, resourcePermission.getPermissionName());

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

   public void removeGlobalResourcePermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               Id<ResourceClassId> accessedResourceClassId,
                                               Id<DomainId> accessedResourceDomainId) throws AccessControlException {

      SQLStatement statement = null;
      try {
         // revoke any existing non-system permissions this accessor has to this resource domain + resource class
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, accessedResourceDomainId);
         statement.setResourceClassId(3, accessedResourceClassId);
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
