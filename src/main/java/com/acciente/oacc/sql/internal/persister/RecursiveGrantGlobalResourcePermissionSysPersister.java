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
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class RecursiveGrantGlobalResourcePermissionSysPersister extends CommonGrantGlobalResourcePermissionSysPersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public RecursiveGrantGlobalResourcePermissionSysPersister(SQLProfile sqlProfile,
                                                             SQLStrings sqlStrings) {
      super(sqlProfile, sqlStrings);
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
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         // get the list of objects of the specified type that the session has access to via global permissions
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourceSystemPermissionId(3, resourcePermission.getSystemPermissionId());
         statement.setBoolean(4, resourcePermission.isWithGrantOption());
         statement.setResourceClassId(5, resourceClassId);
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
         // get the list of objects of the specified type that the session has access to via global permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         statement.setResourceSystemPermissionId(4, resourcePermission.getSystemPermissionId());
         statement.setBoolean(5, resourcePermission.isWithGrantOption());
         statement.setResourceClassId(6, resourceClassId);
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
   public Set<ResourcePermission> getGlobalSysPermissionsIncludeInherited(SQLConnection connection,
                                                                          Resource accessorResource,
                                                                          Id<ResourceClassId> resourceClassId,
                                                                          Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has to the accessed resource
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(getResourceSysPermission(resultSet));
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

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                                    Resource accessorResource) {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has
         SQLResult resultSet;
         Map<String, Map<String, Set<ResourcePermission>>> globalSysPermissionsMap = new HashMap<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermissionSys_ResourceDomainName_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID);
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

            resourcePermissionsForResourceClass.add(getResourceSysPermission(resultSet));
         }
         resultSet.close();

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
         // chose strategy to perform recursive delete based on sql profile
         if (sqlProfile.isRecursiveDeleteEnabled()) {
            // prepare the standard recursive delete statement for domain and its children
            statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantGlobalResourcePermissionSys_withDescendants_BY_AccessedDomainId);

            // revoke any existing system permissions any accessor has to this domain + any resource class
            statement.setResourceDomainId(1, accessedDomainId);
            statement.executeUpdate();
         }
         else {
            // DBMS doesn't support recursive deletion, so we have to remove domain's children's accessors first

            // get descendant domain Ids
            statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_DescendantResourceDomainID_BY_DomainID_ORDERBY_DomainLevel);
            statement.setResourceDomainId(1, accessedDomainId);
            SQLResult resultSet = statement.executeQuery();

            List<Id<DomainId>> descendantDomainIds = new ArrayList<>();

            while (resultSet.next()) {
               descendantDomainIds.add(resultSet.getResourceDomainId("DomainId"));
            }
            closeStatement(statement);

            // delete domains' accessors (in reverse order of domainLevel, to preserve FK constraints)
            statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantGlobalResourcePermissionSys_BY_AccessedDomainId);

            for (int i=descendantDomainIds.size()-1; i >= 0; i--) {
               statement.setResourceDomainId(1, descendantDomainIds.get(i));
               statement.executeUpdate();
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
