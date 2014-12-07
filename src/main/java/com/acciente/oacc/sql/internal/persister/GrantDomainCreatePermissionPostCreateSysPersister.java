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
import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.DomainCreatePermissions;
import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.Resource;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class GrantDomainCreatePermissionPostCreateSysPersister extends Persister {
   private final SQLStrings sqlStrings;

   public GrantDomainCreatePermissionPostCreateSysPersister(SQLStrings sqlStrings) {
      this.sqlStrings = sqlStrings;
   }

   public Set<DomainCreatePermission> getDomainPostCreatePermissions(SQLConnection connection,
                                                                     Resource accessorResource) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainCreatePermissionPostCreateSys_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_InheritLevel_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         SQLResult resultSet = statement.executeQuery();

         // first collect the create permissions that this resource has to resource domains
         Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
         while (resultSet.next()) {
            domainCreatePermissions
                  .add(DomainCreatePermissions.getInstance(DomainPermission.getInstance(resultSet.getDomainSysPermissionName(
                        "PostCreateSysPermissionId"),
                                                                                        resultSet.getBoolean(
                                                                                              "PostCreateIsWithGrant")),
                                                           resultSet.getBoolean("IsWithGrant"),
                                                           resultSet.getInteger("InheritLevel")));
         }
         resultSet.close();

         return domainCreatePermissions;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public Set<DomainCreatePermission> getDirectDomainPostCreatePermissions(SQLConnection connection,
                                                                           Resource accessorResource) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         SQLResult resultSet = statement.executeQuery();

         // collect the create permissions that this resource has to resource domains directly
         Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
         while (resultSet.next()) {
            domainCreatePermissions
                  .add(DomainCreatePermissions.getInstance(DomainPermission.getInstance(resultSet.getDomainSysPermissionName(
                        "PostCreateSysPermissionId"),
                                                                                        resultSet.getBoolean(
                                                                                              "PostCreateIsWithGrant")),
                                                           resultSet.getBoolean("IsWithGrant"),
                                                           0));
         }
         resultSet.close();

         return domainCreatePermissions;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void removeDomainPostCreatePermissions(SQLConnection connection,
                                                 Resource accessorResource) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantDomainCreatePermissionPostCreateSys_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         statement.executeUpdate();
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void addDomainPostCreatePermissions(SQLConnection connection,
                                              Resource accessorResource,
                                              Resource grantorResource,
                                              Set<DomainCreatePermission> domainCreatePermissions) throws AccessControlException {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantDomainCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_IsWithGrant_PostCreateIsWithGrant_PostCreateSysPermissionID);
         for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
            if (!domainCreatePermission.isSystemPermission()
                  && domainCreatePermission.getPostCreateDomainPermission().isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setBoolean(3, domainCreatePermission.isWithGrant());
               statement.setBoolean(4, domainCreatePermission.getPostCreateDomainPermission().isWithGrant());
               statement.setDomainSystemPermissionId(5, domainCreatePermission.getPostCreateDomainPermission().getSystemPermissionId());

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
}
