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

import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class GrantGlobalResourcePermissionSysPersister extends Persister {
   private final SQLStrings sqlStrings;

   public GrantGlobalResourcePermissionSysPersister(SQLStrings sqlStrings) {
      this.sqlStrings = sqlStrings;
   }

   public Set<Resource> getResourcesByGlobalSysPermission(SQLConnection connection,
                                                          Resource accessorResource,
                                                          Id<ResourceClassId> resourceClassId,
                                                          ResourcePermission resourcePermission) throws AccessControlException {
      if (!resourcePermission.isSystemPermission()) {
         throw new AccessControlException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         // get the list of objects of the specified type that the session has access to via global permissions
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_ResourceID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant);
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

   public Set<Resource> getResourcesByGlobalSysPermission(SQLConnection connection,
                                                          Resource accessorResource,
                                                          Id<ResourceClassId> resourceClassId,
                                                          Id<DomainId> resourceDomainId,
                                                          ResourcePermission resourcePermission) throws AccessControlException {
      if (!resourcePermission.isSystemPermission()) {
         throw new AccessControlException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via global permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_ResourceID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant);
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

   public Set<ResourcePermission> getGlobalSysPermissionsIncludeInherited(SQLConnection connection,
                                                                          Resource accessorResource,
                                                                          Id<ResourceClassId> resourceClassId,
                                                                          Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has to the accessed resource
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(ResourcePermissions.getInstance(resultSet.getResourceSysPermissionName(
                                                                          "SysPermissionId"),
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

   public Set<ResourcePermission> getGlobalSysPermissions(SQLConnection connection,
                                                          Resource accessorResource,
                                                          Id<ResourceClassId> resourceClassId,
                                                          Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has to the accessed resource directly
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(ResourcePermissions.getInstance(resultSet.getResourceSysPermissionName(
                  "SysPermissionId"),
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

   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                                    Resource accessorResource)
         throws AccessControlException {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has
         SQLResult resultSet;
         Map<String, Map<String, Set<ResourcePermission>>> globalSysPermissionsMap = new HashMap<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            final String resourceDomainName;
            final String resourceClassName;
            Map<String, Set<ResourcePermission>> permissionsForResourceDomain;
            Set<ResourcePermission> resourcePermissionsForResourceClass;

            resourceDomainName = resultSet.getString("DomainName");
            resourceClassName = resultSet.getString("ResourceClassName");

            if ((permissionsForResourceDomain = globalSysPermissionsMap.get(resourceDomainName)) == null) {
               globalSysPermissionsMap.put(resourceDomainName,
                                           permissionsForResourceDomain = new HashMap<>());
            }

            if ((resourcePermissionsForResourceClass = permissionsForResourceDomain.get(resourceClassName)) == null) {
               permissionsForResourceDomain.put(resourceClassName,
                                                resourcePermissionsForResourceClass = new HashSet<>());
            }

            resourcePermissionsForResourceClass.add(ResourcePermissions.getInstance(resultSet.getResourceSysPermissionName(
                  "SysPermissionId"),
                                                                                    resultSet.getBoolean("IsWithGrant"),
                                                                                    resultSet.getInteger("InheritLevel"),
                                                                                    resultSet.getInteger("DomainLevel")));
         }
         resultSet.close();

         return globalSysPermissionsMap;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalSysPermissions(SQLConnection connection,
                                                                                    Resource accessorResource)
         throws AccessControlException {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has
         SQLResult resultSet;
         Map<String, Map<String, Set<ResourcePermission>>> globalSysPermissionsMap = new HashMap<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            final String resourceDomainName;
            final String resourceClassName;
            Map<String, Set<ResourcePermission>> permissionsForResourceDomain;
            Set<ResourcePermission> resourcePermissionsForResourceClass;

            resourceDomainName = resultSet.getString("DomainName");
            resourceClassName = resultSet.getString("ResourceClassName");

            if ((permissionsForResourceDomain = globalSysPermissionsMap.get(resourceDomainName)) == null) {
               globalSysPermissionsMap.put(resourceDomainName,
                                           permissionsForResourceDomain = new HashMap<>());
            }

            if ((resourcePermissionsForResourceClass = permissionsForResourceDomain.get(resourceClassName)) == null) {
               permissionsForResourceDomain.put(resourceClassName,
                                                resourcePermissionsForResourceClass = new HashSet<>());
            }

            resourcePermissionsForResourceClass
                  .add(ResourcePermissions.getInstance(resultSet.getResourceSysPermissionName("SysPermissionId"),
                                                       resultSet.getBoolean("IsWithGrant"),
                                                       0,
                                                       0));
         }
         resultSet.close();

         return globalSysPermissionsMap;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void addGlobalSysPermissions(SQLConnection connection,
                                       Resource accessorResource,
                                       Id<ResourceClassId> accessedResourceClassId,
                                       Id<DomainId> accessedResourceDomainId,
                                       Set<ResourcePermission> requestedResourcePermissions,
                                       Resource grantorResource) throws AccessControlException {
      SQLStatement statement = null;
      try {
         // add the new system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantGlobalResourcePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionID);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setResourceDomainId(3, accessedResourceDomainId);
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

   public void removeGlobalSysPermissions(SQLConnection connection,
                                          Resource accessorResource,
                                          Id<ResourceClassId> accessedResourceClassId,
                                          Id<DomainId> accessedResourceDomainId) throws AccessControlException {

      SQLStatement statement = null;
      try {
         // revoke any existing system permissions this accessor has to this resource domain + resource class
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID);
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