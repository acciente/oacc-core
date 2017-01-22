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
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class NonRecursiveGrantDomainCreatePermissionPostCreateSysPersister extends CommonGrantDomainCreatePermissionPostCreateSysPersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public NonRecursiveGrantDomainCreatePermissionPostCreateSysPersister(SQLProfile sqlProfile,
                                                                        SQLStrings sqlStrings) {
      super(sqlProfile, sqlStrings);
   }

   @Override
   public Set<DomainCreatePermission> getDomainCreatePostCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                              Resource accessorResource) {
      SQLStatement statement = null;

      try {
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // now accumulate the permissions on the accessed resource from each of the (inherited) accessors
         Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantDomainCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            statement.setResourceId(1, accessorResourceId);
            SQLResult resultSet = statement.executeQuery();

            while (resultSet.next()) {
               domainCreatePermissions.add(getDomainCreatePostCreateSysPermission(resultSet));
            }
            resultSet.close();
         }

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
