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
import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.DomainPermissions;
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.SQLProfile;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public abstract class CommonGrantDomainCreatePermissionPostCreateSysPersister extends Persister implements GrantDomainCreatePermissionPostCreateSysPersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public CommonGrantDomainCreatePermissionPostCreateSysPersister(SQLProfile sqlProfile,
                                                                  SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public abstract Set<DomainCreatePermission> getDomainCreatePostCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                                       Resource accessorResource);

   @Override
   public Set<DomainCreatePermission> getDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                                              Resource accessorResource) {
      SQLStatement statement = null;

      try {
         statement = connection
               .prepareStatement(sqlStrings.SQL_findInGrantDomainCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         SQLResult resultSet = statement.executeQuery();

         // collect the create permissions that this resource has to domains directly
         Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
         while (resultSet.next()) {
            domainCreatePermissions.add(getDomainCreatePostCreateSysPermission(resultSet));
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

   protected static DomainCreatePermission getDomainCreatePostCreateSysPermission(SQLResult resultSet) throws SQLException {
      final DomainPermission postCreatePermission;
      final String postCreateSysPermissionName = resultSet.getDomainSysPermissionName("PostCreateSysPermissionId");

      if (resultSet.getBoolean("PostCreateIsWithGrant")) {
         postCreatePermission = DomainPermissions.getInstanceWithGrantOption(postCreateSysPermissionName);
      }
      else {
         postCreatePermission = DomainPermissions.getInstance(postCreateSysPermissionName);
      }

      if (resultSet.getBoolean("IsWithGrant")) {
         return DomainCreatePermissions.getInstanceWithGrantOption(postCreatePermission);
      }
      else {
         return  DomainCreatePermissions.getInstance(postCreatePermission);
      }
   }

   @Override
   public void removeDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                          Resource accessorResource) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID);
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
   public void removeDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                          Resource accessorResource,
                                                          Set<DomainCreatePermission> domainCreatePermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID_PostCreateSysPermissionID);
         for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
            if (!domainCreatePermission.isSystemPermission()
                  && domainCreatePermission.getPostCreateDomainPermission().isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setDomainSystemPermissionId(2, domainCreatePermission.getPostCreateDomainPermission().getSystemPermissionId());

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
   public void addDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                       Resource accessorResource,
                                                       Resource grantorResource,
                                                       Set<DomainCreatePermission> domainCreatePermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantDomainCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_IsWithGrant_PostCreateIsWithGrant_PostCreateSysPermissionID);
         for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
            if (!domainCreatePermission.isSystemPermission()
                  && domainCreatePermission.getPostCreateDomainPermission().isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setBoolean(3, domainCreatePermission.isWithGrantOption());
               statement.setBoolean(4, domainCreatePermission.getPostCreateDomainPermission().isWithGrantOption());
               statement.setDomainSystemPermissionId(5, domainCreatePermission.getPostCreateDomainPermission().getSystemPermissionId());

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
   public void updateDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                          Resource accessorResource,
                                                          Resource grantorResource,
                                                          Set<DomainCreatePermission> domainCreatePermissions) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_updateInGrantDomainCreatePermissionPostCreateSys_SET_GrantorID_IsWithGrant_PostCreateIsWithGrant_BY_AccessorID_PostCreateSysPermissionID);
         for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
            if (!domainCreatePermission.isSystemPermission()
                  && domainCreatePermission.getPostCreateDomainPermission().isSystemPermission()) {
               statement.setResourceId(1, grantorResource);
               statement.setBoolean(2, domainCreatePermission.isWithGrantOption());
               statement.setBoolean(3, domainCreatePermission.getPostCreateDomainPermission().isWithGrantOption());
               statement.setResourceId(4, accessorResource);
               statement.setDomainSystemPermissionId(5, domainCreatePermission.getPostCreateDomainPermission().getSystemPermissionId());

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
