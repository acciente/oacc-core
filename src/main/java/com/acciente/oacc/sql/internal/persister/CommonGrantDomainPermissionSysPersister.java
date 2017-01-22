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
import com.acciente.oacc.DomainPermissions;
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class CommonGrantDomainPermissionSysPersister extends Persister implements GrantDomainPermissionSysPersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public static final DomainPermission DOMAIN_PERMISSION_SUPER_USER = DomainPermissions
         .getInstance(DomainPermissions.SUPER_USER);

   public CommonGrantDomainPermissionSysPersister(SQLProfile sqlProfile,
                                                  SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public abstract Set<Resource> getResourcesByDomainSuperUserPermission(SQLConnection connection,
                                                                         Resource accessorResource,
                                                                         Id<ResourceClassId> resourceClassId);

   @Override
   public abstract Set<Resource> getResourcesByDomainSuperUserPermission(SQLConnection connection,
                                                                         Resource accessorResource,
                                                                         Id<ResourceClassId> resourceClassId,
                                                                         Id<DomainId> resourceDomainId);

   @Override
   public abstract Set<DomainPermission> getDomainSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                 Resource accessorResource,
                                                                                 Id<DomainId> resourceDomainId);

   @Override
   public Set<DomainPermission> getDomainSysPermissions(SQLConnection connection,
                                                        Resource accessorResource,
                                                        Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_withoutInheritance_SysPermissionID_IsWithGrant_BY_AccessorID_DomainID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         SQLResult resultSet = statement.executeQuery();

         // collect the create permissions that this resource has to the domain directly
         Set<DomainPermission> domainPermissions = new HashSet<>();
         while (resultSet.next()) {
            // on the domains only pre-defined system permissions are expected
            domainPermissions.add(getDomainSysPermission(resultSet));
         }
         resultSet.close();

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
   public abstract Map<String, Set<DomainPermission>> getDomainSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                              Resource accessorResource);

   @Override
   public Map<String, Set<DomainPermission>> getDomainSysPermissions(SQLConnection connection,
                                                                     Resource accessorResource) {
      SQLStatement statement = null;

      try {
         // collect the create permissions that this resource has to each domain
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainPermissionSys_withoutInheritance_ResourceDomainName_SysPermissionID_IsWithGrant_BY_AccessorID);
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

            // on the domains only pre-defined system permissions are expected
            domainPermissions.add(getDomainSysPermission(resultSet));
         }
         resultSet.close();

         return domainPermissionsMap;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   protected static DomainPermission getDomainSysPermission(SQLResult resultSet) throws SQLException {
      final String sysPermissionName = resultSet.getDomainSysPermissionName("SysPermissionId");

      if (resultSet.getBoolean("IsWithGrant")) {
         return DomainPermissions.getInstanceWithGrantOption(sysPermissionName);
      }
      else {
         return DomainPermissions.getInstance(sysPermissionName);
      }
   }

   @Override
   public void addDomainSysPermissions(SQLConnection connection,
                                       Resource accessorResource,
                                       Resource grantorResource,
                                       Id<DomainId> resourceDomainId,
                                       Set<DomainPermission> requestedDomainPermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantDomainPermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_SysPermissionID);

         for (DomainPermission domainPermission : requestedDomainPermissions) {
            statement.setResourceId(1, accessorResource);
            statement.setResourceId(2, grantorResource);
            statement.setResourceDomainId(3, resourceDomainId);
            statement.setBoolean(4, domainPermission.isWithGrantOption());
            statement.setDomainSystemPermissionId(5, domainPermission.getSystemPermissionId());

            assertOneRowInserted(statement.executeUpdate());
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
   public void updateDomainSysPermissions(SQLConnection connection,
                                          Resource accessorResource,
                                          Resource grantorResource,
                                          Id<DomainId> resourceDomainId,
                                          Set<DomainPermission> requestedDomainPermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_updateInGrantDomainPermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedDomainID_SysPermissionID);

         for (DomainPermission domainPermission : requestedDomainPermissions) {
            statement.setResourceId(1, grantorResource);
            statement.setBoolean(2, domainPermission.isWithGrantOption());
            statement.setResourceId(3, accessorResource);
            statement.setResourceDomainId(4, resourceDomainId);
            statement.setDomainSystemPermissionId(5, domainPermission.getSystemPermissionId());

            assertOneRowUpdated(statement.executeUpdate());
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
   public void removeAllDomainSysPermissions(SQLConnection connection,
                                             Resource accessorResource) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainPermissionSys_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
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
   public abstract void removeAllDomainSysPermissions(SQLConnection connection, Id<DomainId> domainId) ;

   @Override
   public void removeDomainSysPermissions(SQLConnection connection,
                                          Resource accessorResource,
                                          Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
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
   public void removeDomainSysPermissions(SQLConnection connection,
                                          Resource accessorResource,
                                          Id<DomainId> resourceDomainId,
                                          Set<DomainPermission> requestedDomainPermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainPermissionSys_BY_AccessorID_AccessedDomainID_SysPermissionID);
         for (DomainPermission domainPermission : requestedDomainPermissions) {
            statement.setResourceId(1, accessorResource);
            statement.setResourceDomainId(2, resourceDomainId);
            statement.setDomainSystemPermissionId(3, domainPermission.getSystemPermissionId());

            assertOneRowUpdated(statement.executeUpdate());
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
