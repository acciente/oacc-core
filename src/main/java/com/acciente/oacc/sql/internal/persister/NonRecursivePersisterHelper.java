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
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class NonRecursivePersisterHelper {
   protected static Set<Id<ResourceId>> getInheritedAccessorResourceIds(SQLStrings sqlStrings,
                                                                        SQLConnection connection,
                                                                        Resource accessorResource) throws SQLException {
      SQLStatement statement = null;
      Set<Id<ResourceId>> allAccessorResourceIds = new HashSet<>();
      allAccessorResourceIds.add(Id.<ResourceId>from(accessorResource.getId()));
      Set<Id<ResourceId>> previousAccessorResourceIds = new HashSet<>(allAccessorResourceIds);

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_directInheritance_ResourceID_BY_AccessorID);

         while (!previousAccessorResourceIds.isEmpty()) {
            Set<Id<ResourceId>> newestAccessorResourceIds = new HashSet<>();

            for (Id<ResourceId> accessorResourceId : previousAccessorResourceIds) {
               statement.setResourceId(1, accessorResourceId);
               SQLResult resultSet = statement.executeQuery();

               while (resultSet.next()) {
                  newestAccessorResourceIds.add(resultSet.getResourceId("ResourceId"));
               }
               resultSet.close();
            }
            allAccessorResourceIds.addAll(newestAccessorResourceIds);
            previousAccessorResourceIds = newestAccessorResourceIds;
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         Persister.closeStatement(statement);
      }

      return allAccessorResourceIds;
   }

   protected static Set<Id<DomainId>> getDescendantDomainIds(SQLStrings sqlStrings,
                                                             SQLConnection connection,
                                                             Id<DomainId> parentDomainId) throws SQLException {
      SQLStatement statement = null;
      Set<Id<DomainId>> allDomainIds = new HashSet<>();
      allDomainIds.add(parentDomainId);
      Set<Id<DomainId>> previousDomainIds = new HashSet<>(allDomainIds);

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_DirectDescendantResourceDomainName_BY_DomainID);

         while (!previousDomainIds.isEmpty()) {
            Set<Id<DomainId>> newestDomainIds = new HashSet<>();

            for (Id<DomainId> domainId : previousDomainIds) {
               statement.setResourceDomainId(1, domainId);
               SQLResult resultSet = statement.executeQuery();

               while (resultSet.next()) {
                  newestDomainIds.add(resultSet.getResourceDomainId("DomainId"));
               }
               resultSet.close();
            }
            allDomainIds.addAll(newestDomainIds);
            previousDomainIds = newestDomainIds;
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         Persister.closeStatement(statement);
      }

      return allDomainIds;
   }
}
