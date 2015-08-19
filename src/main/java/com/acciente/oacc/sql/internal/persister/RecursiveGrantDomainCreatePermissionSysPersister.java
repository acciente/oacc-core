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

import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.DomainCreatePermissions;
import com.acciente.oacc.Resource;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class RecursiveGrantDomainCreatePermissionSysPersister extends CommonGrantDomainCreatePermissionSysPersister {
   public RecursiveGrantDomainCreatePermissionSysPersister(SQLStrings sqlStrings) {
      super(sqlStrings);
   }

   @Override
   public Set<DomainCreatePermission> getDomainCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                    Resource accessorResource) {
      SQLStatement statement = null;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainCreatePermissionSys_SysPermissionID_IsWithGrant_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         SQLResult resultSet = statement.executeQuery();

         // collect the create permissions that this resource has to domains
         Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
         while (resultSet.next()) {
            domainCreatePermissions
                  .add(DomainCreatePermissions.getInstance(resultSet
                                                                 .getDomainCreateSysPermissionName("SysPermissionId"),
                                                           resultSet.getBoolean("IsWithGrant")));
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
}
