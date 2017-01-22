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

import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.DomainCreatePermissions;
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.SQLProfile;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public abstract class CommonGrantDomainCreatePermissionSysPersister extends Persister implements GrantDomainCreatePermissionSysPersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public CommonGrantDomainCreatePermissionSysPersister(SQLProfile sqlProfile,
                                                        SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public abstract Set<DomainCreatePermission> getDomainCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                             Resource accessorResource);

   @Override
   public Set<DomainCreatePermission> getDomainCreateSysPermissions(SQLConnection connection,
                                                                    Resource accessorResource) {
      SQLStatement statement = null;

      try {
         statement = connection
               .prepareStatement(sqlStrings.SQL_findInGrantDomainCreatePermissionSys_withoutInheritance_SysPermissionID_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         SQLResult resultSet = statement.executeQuery();

         // first collect the create permissions that this resource has to domains directly
         Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
         while (resultSet.next()) {
            domainCreatePermissions.add(getDomainCreateSysPermission(resultSet));
         }
         resultSet.close();

         return domainCreatePermissions;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   protected static DomainCreatePermission getDomainCreateSysPermission(SQLResult resultSet) throws SQLException {
      final String sysPermissionName = resultSet.getDomainCreateSysPermissionName("SysPermissionId");

      if (resultSet.getBoolean("IsWithGrant")) {
         return DomainCreatePermissions.getInstanceWithGrantOption(sysPermissionName);
      }
      else {
         return DomainCreatePermissions.getInstance(sysPermissionName);
      }
   }

   @Override
   public void addDomainCreateSysPermissions(SQLConnection connection,
                                             Resource accessorResource,
                                             Resource grantorResource,
                                             Set<DomainCreatePermission> domainCreatePermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantDomainCreatePermissionSys_WITH_AccessorID_GrantorID_IsWithGrant_SysPermissionID);
         for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
            if (domainCreatePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setBoolean(3, domainCreatePermission.isWithGrantOption());
               statement.setDomainCreateSystemPermissionId(4, domainCreatePermission.getSystemPermissionId());

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
   public void updateDomainCreateSysPermissions(SQLConnection connection,
                                                Resource accessorResource,
                                                Resource grantorResource,
                                                Set<DomainCreatePermission> domainCreatePermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_updateInGrantDomainCreatePermissionSys_SET_GrantorID_IsWithGrant_BY_AccessorID_SysPermissionID);
         for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
            if (domainCreatePermission.isSystemPermission()) {
               statement.setResourceId(1, grantorResource);
               statement.setBoolean(2, domainCreatePermission.isWithGrantOption());
               statement.setResourceId(3, accessorResource);
               statement.setDomainCreateSystemPermissionId(4, domainCreatePermission.getSystemPermissionId());

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
   public void removeDomainCreateSysPermissions(SQLConnection connection,
                                                Resource accessorResource) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainCreatePermissionSys_BY_AccessorID);
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
   public void removeDomainCreateSysPermissions(SQLConnection connection,
                                                Resource accessorResource,
                                                Set<DomainCreatePermission> domainCreatePermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainCreatePermissionSys_BY_AccessorID_SysPermissionID);
         for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
            if (domainCreatePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setDomainCreateSystemPermissionId(2, domainCreatePermission.getSystemPermissionId());

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
