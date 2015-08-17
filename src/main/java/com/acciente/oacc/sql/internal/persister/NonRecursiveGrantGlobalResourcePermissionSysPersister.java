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
import com.acciente.oacc.ResourceCreatePermission;
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.sql.SQLDialect;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NonRecursiveGrantGlobalResourcePermissionSysPersister extends CommonGrantGlobalResourcePermissionSysPersister {
   public NonRecursiveGrantGlobalResourcePermissionSysPersister(SQLStrings sqlStrings) {
      super(sqlStrings);
   }

   @Override
   public Set<Resource> getResourcesByGlobalSysPermission(SQLConnection connection,
                                                          Resource accessorResource,
                                                          Id<ResourceClassId> resourceClassId,
                                                          ResourcePermission resourcePermission) {
      if (!resourcePermission.isSystemPermission()) {
         throw new IllegalArgumentException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // now accumulate the objects of the specified type that each (inherited) accessor has the specified permission to
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_ResourceID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            statement.setResourceId(1, accessorResourceId);
            statement.setResourceClassId(2, resourceClassId);
            statement.setResourceSystemPermissionId(3, resourcePermission.getSystemPermissionId());
            statement.setBoolean(4, resourcePermission.isWithGrant());
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               resources.add(resultSet.getResource("ResourceId"));
            }
            resultSet.close();
         }

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
   public Set<Resource> getResourcesByGlobalSysPermission(SQLConnection connection,
                                                          Resource accessorResource,
                                                          Id<ResourceClassId> resourceClassId,
                                                          Id<DomainId> resourceDomainId,
                                                          ResourcePermission resourcePermission) {
      if (!resourcePermission.isSystemPermission()) {
         throw new IllegalArgumentException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // then get all the descendants of the specified domain
         final Set<Id<DomainId>> descendantDomainIds
               = NonRecursivePersisterHelper.getDescendantDomainIdsOrderedByAscendingLevel(sqlStrings,
                                                                                           connection,
                                                                                           resourceDomainId);

         // now accumulate the objects of the specified type that each (inherited) accessor
         // has the specified permission to in each of the descendant domains
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_ResourceID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            for (Id<DomainId> descendantDomainId : descendantDomainIds) {
               statement.setResourceId(1, accessorResourceId);
               statement.setResourceDomainId(2, descendantDomainId);
               statement.setResourceClassId(3, resourceClassId);
               statement.setResourceSystemPermissionId(4, resourcePermission.getSystemPermissionId());
               statement.setBoolean(5, resourcePermission.isWithGrant());
               resultSet = statement.executeQuery();

               while (resultSet.next()) {
                  resources.add(resultSet.getResource("ResourceId"));
               }
               resultSet.close();
            }
         }

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
   public Set<ResourcePermission> getGlobalSysPermissionsIncludeInherited(SQLConnection connection,
                                                                          Resource accessorResource,
                                                                          Id<ResourceClassId> resourceClassId,
                                                                          Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;
      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // get the ancestors of the specified domain, to which the accessors could also have permissions
         final Set<Id<DomainId>> ancestorDomainIds
               = NonRecursivePersisterHelper.getAncestorDomainIds(sqlStrings, connection, resourceDomainId);

         // now collect the sys-permissions any accessor resource has to the specified domain or its ancestors
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            for (Id<DomainId> domainId : ancestorDomainIds) {
               statement.setResourceId(1, accessorResourceId);
               statement.setResourceDomainId(2, domainId);
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
            }
         }
         return resourcePermissions;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                                    Resource accessorResource) {
      SQLStatement statement = null;
      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // second, get all the global resource permissions the accessors directly have access to
         SQLResult resultSet;
         Map<String, Map<String, Set<ResourcePermission>>> globalSysPermissionsMap = new HashMap<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_withoutInheritance_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            statement.setResourceId(1, accessorResourceId);
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               final String resourceDomainName = resultSet.getString("DomainName");
               final String resourceClassName = resultSet.getString("ResourceClassName");

               Map<String, Set<ResourcePermission>> permissionsForResourceDomain
                     = globalSysPermissionsMap.get(resourceDomainName);
               if (permissionsForResourceDomain == null) {
                  permissionsForResourceDomain = new HashMap<>();
                  globalSysPermissionsMap.put(resourceDomainName, permissionsForResourceDomain);
               }

               Set<ResourcePermission> permissionsForResourceClass
                     = permissionsForResourceDomain.get(resourceClassName);
               if (permissionsForResourceClass == null) {
                  permissionsForResourceClass = new HashSet<>();
                  permissionsForResourceDomain.put(resourceClassName, permissionsForResourceClass);
               }

               permissionsForResourceClass
                     .add(ResourcePermissions.getInstance(resultSet.getResourceSysPermissionName("SysPermissionId"),
                                                          resultSet.getBoolean("IsWithGrant"),
                                                          0,
                                                          0));
            }
            resultSet.close();
         }

         // then apply each domain's direct permissions to all its descendants
         // !! DON'T UPDATE THE PERMISSION-MAP WHILE ITERATING OVER ITS KEY-SET !! (get a copy of the key-set instead)
         Set<String> directDomainNames = new HashSet<>(globalSysPermissionsMap.keySet());
         for (String directDomainName : directDomainNames) {
            Set<String> descendentDomains = NonRecursivePersisterHelper.getDescendantDomainNames(sqlStrings,
                                                                                                 connection,
                                                                                                 directDomainName);

            for (String descendentDomain : descendentDomains) {
               Map<String, Set<ResourcePermission>> permissionsForResourceDomain
                     = globalSysPermissionsMap.get(descendentDomain);
               if (permissionsForResourceDomain == null) {
                  permissionsForResourceDomain = new HashMap<>();
                  globalSysPermissionsMap.put(descendentDomain, permissionsForResourceDomain);
               }

               if (!descendentDomain.equals(directDomainName)) {
                  final Map<String, Set<ResourcePermission>> sourceResourceClassPermissionsMap
                        = globalSysPermissionsMap.get(directDomainName);

                  for (String resourceClassName : sourceResourceClassPermissionsMap.keySet()) {
                     Set<ResourcePermission> permissionsForResourceClass
                           = permissionsForResourceDomain.get(resourceClassName);
                     if (permissionsForResourceClass == null) {
                        permissionsForResourceClass = new HashSet<>();
                        permissionsForResourceDomain.put(resourceClassName, permissionsForResourceClass);
                     }

                     permissionsForResourceClass.addAll(sourceResourceClassPermissionsMap.get(resourceClassName));
                  }
               }
            }
         }

         return globalSysPermissionsMap;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void removeAllGlobalSysPermissions(SQLConnection connection,
                                             Id<DomainId> accessedDomainId) {
      SQLStatement statement = null;
      try {
         // get descendant domain Ids
         List<Id<DomainId>> descendantDomainIds
               = new ArrayList<>(NonRecursivePersisterHelper.getDescendantDomainIdsOrderedByAscendingLevel(sqlStrings,
                                                                                                           connection,
                                                                                                           accessedDomainId));

         // delete domains' accessors (in reverse order of domainLevel, to preserve FK constraints)
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessedDomainId);

         for (int i=descendantDomainIds.size()-1; i >= 0; i--) {
            statement.setResourceDomainId(1, descendantDomainIds.get(i));
            statement.executeUpdate();
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
