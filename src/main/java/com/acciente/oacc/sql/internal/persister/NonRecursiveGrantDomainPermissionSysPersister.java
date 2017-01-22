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

import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class NonRecursiveGrantDomainPermissionSysPersister extends CommonGrantDomainPermissionSysPersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public NonRecursiveGrantDomainPermissionSysPersister(SQLProfile sqlProfile,
                                                        SQLStrings sqlStrings) {
      super(sqlProfile, sqlStrings);
   }

   @Override
   public Set<Resource> getResourcesByDomainSuperUserPermission(SQLConnection connection,
                                                                Resource accessorResource,
                                                                Id<ResourceClassId> resourceClassId) {
      SQLStatement statement = null;
      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // secondly get all the domains the accessors directly have access to
         SQLResult resultSet;
         final Set<Id<DomainId>> directDomainIds = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_withoutInheritance_ResourceDomainId_BY_AccessorID_SysPermissionID_IsWithGrant);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            statement.setResourceId(1, accessorResourceId);
            statement.setDomainSystemPermissionId(2, DOMAIN_PERMISSION_SUPER_USER.getSystemPermissionId());
            statement.setBoolean(3, false);
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               directDomainIds.add(resultSet.getResourceDomainId("AccessedDomainId"));
            }
            resultSet.close();
         }
         closeStatement(statement);

         // then get all the descendants of the directly accessible domains
         final Set<Id<DomainId>> accessibleDomainIds = new HashSet<>();
         for (Id<DomainId> directDomainId : directDomainIds) {
            accessibleDomainIds
                  .addAll(NonRecursivePersisterHelper.getDescendantDomainIdsOrderedByAscendingLevel(sqlStrings,
                                                                                                    connection,
                                                                                                    directDomainId));
         }

         // now get resources of the specified class that the session has access to via domain super user permissions
         final Set<Resource> resources = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_withoutInheritance_ResourceId_ExternalId_BY_ResourceClassID_DomainID);

         for (Id<DomainId> domainId : accessibleDomainIds) {
            statement.setResourceClassId(1, resourceClassId);
            statement.setResourceDomainId(2, domainId);
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               resources.add(resultSet.getResource("ResourceId", "ExternalId"));
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
   public Set<Resource> getResourcesByDomainSuperUserPermission(SQLConnection connection,
                                                                Resource accessorResource,
                                                                Id<ResourceClassId> resourceClassId,
                                                                Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;
      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // secondly get all the domains the accessors directly have access to
         SQLResult resultSet;
         final Set<Id<DomainId>> directDomainIds = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_withoutInheritance_ResourceDomainId_BY_AccessorID_SysPermissionID_IsWithGrant);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            statement.setResourceId(1, accessorResourceId);
            statement.setDomainSystemPermissionId(2, DOMAIN_PERMISSION_SUPER_USER.getSystemPermissionId());
            statement.setBoolean(3, false);
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               directDomainIds.add(resultSet.getResourceDomainId("AccessedDomainId"));
            }
            resultSet.close();
         }
         closeStatement(statement);

         // then get all the descendants of the directly accessible domains
         final Set<Id<DomainId>> accessibleDomainIds = new HashSet<>();
         for (Id<DomainId> directDomainId : directDomainIds) {
            accessibleDomainIds
                  .addAll(NonRecursivePersisterHelper.getDescendantDomainIdsOrderedByAscendingLevel(sqlStrings,
                                                                                                    connection,
                                                                                                    directDomainId));
         }

         // also get the descendents of the specified domain
         final Set<Id<DomainId>> descendantDomainIds
               = NonRecursivePersisterHelper.getDescendantDomainIdsOrderedByAscendingLevel(sqlStrings,
                                                                                           connection,
                                                                                           resourceDomainId);

         // next, filter the accessible domains by the specified sub-domains
         accessibleDomainIds.retainAll(descendantDomainIds);

         // now get resources of the specified class that the session has access to via domain super user permissions
         final Set<Resource> resources = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_withoutInheritance_ResourceId_ExternalId_BY_ResourceClassID_DomainID);

         for (Id<DomainId> domainId : accessibleDomainIds) {
            statement.setResourceClassId(1, resourceClassId);
            statement.setResourceDomainId(2, domainId);
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               resources.add(resultSet.getResource("ResourceId", "ExternalId"));
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
   public Set<DomainPermission> getDomainSysPermissionsIncludeInherited(SQLConnection connection,
                                                                        Resource accessorResource,
                                                                        Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;

      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // get the ancestors of the specified domain, to which the accessors could also have permissions
         final Set<Id<DomainId>> ancestorDomainIds = NonRecursivePersisterHelper.getAncestorDomainIds(sqlStrings,
                                                                                                      connection,
                                                                                                      resourceDomainId);

         // now collect the sys-permissions any accessor resource has to the specified domain or its ancestors
         Set<DomainPermission> domainPermissions = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_DomainID);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            for (Id<DomainId> domainId : ancestorDomainIds) {
               statement.setResourceId(1, accessorResourceId);
               statement.setResourceDomainId(2, domainId);
               SQLResult resultSet = statement.executeQuery();

               while (resultSet.next()) {
                  // on the domains only pre-defined system permissions are expected
                  domainPermissions.add(getDomainSysPermission(resultSet));
               }
               resultSet.close();
            }
         }

         return domainPermissions;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public Map<String, Set<DomainPermission>> getDomainSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                     Resource accessorResource) {
      SQLStatement statement = null;

      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // second, get all the domain permissions the accessors directly have access to
         SQLResult resultSet;
         final Map<String, Set<DomainPermission>> domainPermissionsMap = new HashMap<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_withoutInheritance_ResourceDomainName_SysPermissionID_IsWithGrant_BY_AccessorID);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            statement.setResourceId(1, accessorResourceId);
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               final String resourceDomainName = resultSet.getString("DomainName");

               Set<DomainPermission> domainPermissions = domainPermissionsMap.get(resourceDomainName);

               if (domainPermissions == null) {
                  domainPermissions = new HashSet<>();
                  domainPermissionsMap.put(resourceDomainName, domainPermissions);
               }

               // on the domains only pre-defined system permissions are expected
               domainPermissions.add(getDomainSysPermission(resultSet));
            }
            resultSet.close();
         }
         closeStatement(statement);
         statement = null;

         // then apply each domain's direct permissions to all its descendants
         // !! DON'T UPDATE THE PERMISSION-MAP WHILE ITERATING OVER ITS KEY-SET !! (get a copy of the key-set instead)
         Set<String> directDomainNames = new HashSet<>(domainPermissionsMap.keySet());
         for (String directDomainName : directDomainNames) {
            Set<String> descendentDomains = NonRecursivePersisterHelper.getDescendantDomainNames(sqlStrings,
                                                                                                 connection,
                                                                                                 directDomainName);

            for (String descendentDomain : descendentDomains) {
               Set<DomainPermission> domainPermissions = domainPermissionsMap.get(descendentDomain);

               if (domainPermissions == null) {
                  domainPermissions = new HashSet<>();
                  domainPermissionsMap.put(descendentDomain, domainPermissions);
               }

               if (!descendentDomain.equals(directDomainName)) {
                  domainPermissions.addAll(domainPermissionsMap.get(directDomainName));
               }
            }
         }

         return domainPermissionsMap;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void removeAllDomainSysPermissions(SQLConnection connection, Id<DomainId> domainId) {
      SQLStatement statement = null;

      try {
         // get descendant domain Ids
         List<Id<DomainId>> descendantDomainIds
               = new ArrayList<>(NonRecursivePersisterHelper.getDescendantDomainIdsOrderedByAscendingLevel(sqlStrings,
                                                                                                           connection,
                                                                                                           domainId));

         // delete domains' accessors (in reverse order of domainLevel, to preserve FK constraints)
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainPermissionSys_BY_AccessedDomainID);

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
