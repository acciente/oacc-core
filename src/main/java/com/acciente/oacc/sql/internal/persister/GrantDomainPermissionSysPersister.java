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
import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.DomainPermissions;
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class GrantDomainPermissionSysPersister extends Persister {
   private final SQLStrings sqlStrings;

   public static final DomainPermission DOMAIN_PERMISSION_SUPER_USER = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);

   public GrantDomainPermissionSysPersister(SQLStrings sqlStrings) {
      this.sqlStrings = sqlStrings;
   }

   public Set<Resource> getResourcesByDomainSuperUserPermission(SQLConnection connection,
                                                                Resource accessorResource,
                                                                Id<ResourceClassId> resourceClassId) throws AccessControlException {
      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via domain super user permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_ResourceID_BY_AccessorID_SysPermissionID_IsWithGrant_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setDomainSystemPermissionId(2, DOMAIN_PERMISSION_SUPER_USER.getSystemPermissionId());
         statement.setBoolean(3, false);
         statement.setResourceClassId(4, resourceClassId);
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

   public Set<Resource> getResourcesByDomainSuperUserPermission(SQLConnection connection,
                                                                Resource accessorResource,
                                                                Id<ResourceClassId> resourceClassId,
                                                                Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via domain super user permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_ResourceID_BY_AccessorID_DomainID_SysPermissionID_IsWithGrant_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setDomainSystemPermissionId(3, DOMAIN_PERMISSION_SUPER_USER.getSystemPermissionId());
         statement.setBoolean(4, false);
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

   public Set<DomainPermission> getDomainSysPermissionsIncludeInherited(SQLConnection connection,
                                                                        Resource accessorResource,
                                                                        Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID_DomainID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         SQLResult resultSet = statement.executeQuery();

         // first collect the create permissions that this resource has to resource domains
         Set<DomainPermission> domainPermissions = new HashSet<>();
         while (resultSet.next()) {
            // on the resource domains only pre-defined system permissions are expected
            domainPermissions
                  .add(DomainPermissions.getInstance(resultSet.getDomainSysPermissionName("SysPermissionId"),
                                                     resultSet.getBoolean("IsWithGrant"),
                                                     resultSet.getInteger("InheritLevel"),
                                                     resultSet.getInteger("DomainLevel")));
         }
         resultSet.close();

         return domainPermissions;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Set<DomainPermission> getDomainSysPermissions(SQLConnection connection,
                                                        Resource accessorResource,
                                                        Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_DomainID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         SQLResult resultSet = statement.executeQuery();

         // collect the create permissions that this resource has to the resource domain directly
         Set<DomainPermission> domainPermissions = new HashSet<>();
         while (resultSet.next()) {
            // on the resource domains only pre-defined system permissions are expected
            domainPermissions
                  .add(DomainPermissions.getInstance(resultSet.getDomainSysPermissionName("SysPermissionId"),
                                                     resultSet.getBoolean("IsWithGrant"),
                                                     0,
                                                     0));
         }
         resultSet.close();

         return domainPermissions;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Map<String, Set<DomainPermission>> getDomainSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                     Resource accessorResource) throws AccessControlException {
      SQLStatement statement = null;

      try {
         // collect the create permissions that this resource has to each resource domains
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_ResourceDomainName_SysPermissionID_IsWithGrant_InheritLevel_DomainLevel_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         SQLResult resultSet = statement.executeQuery();

         final Map<String, Set<DomainPermission>> domainPermissionsMap = new HashMap<>();

         while (resultSet.next()) {
            final String resourceDomainName = resultSet.getString("DomainName");

            Set<DomainPermission> domainPermissions = domainPermissionsMap.get(resourceDomainName);

            if (domainPermissions == null) {
               domainPermissionsMap.put(resourceDomainName,
                                        domainPermissions = new HashSet<>());
            }

            // on the resource domains only pre-defined system permissions are expected
            domainPermissions
                  .add(DomainPermissions.getInstance(resultSet.getDomainSysPermissionName("SysPermissionId"),
                                                     resultSet.getBoolean("IsWithGrant"),
                                                     resultSet.getInteger("InheritLevel"),
                                                     resultSet.getInteger("DomainLevel")));
         }
         resultSet.close();

         return domainPermissionsMap;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void addDomainSysPermissions(SQLConnection connection,
                                       Resource accessorResource,
                                       Resource grantorResource,
                                       Id<DomainId> resourceDomainId,
                                       Set<DomainPermission> requestedDomainPermissions) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantDomainPermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_SysPermissionID);

         for (DomainPermission domainPermission : requestedDomainPermissions) {
            statement.setResourceId(1, accessorResource);
            statement.setResourceId(2, grantorResource);
            statement.setResourceDomainId(3, resourceDomainId);
            statement.setBoolean(4, domainPermission.isWithGrant());
            statement.setDomainSystemPermissionId(5, domainPermission.getSystemPermissionId());

            assertOneRowInserted(statement.executeUpdate());
         }
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void removeDomainSysPermissions(SQLConnection connection,
                                          Resource accessorResource,
                                          Id<DomainId> resourceDomainId) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
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
