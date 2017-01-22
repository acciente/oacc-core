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
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

public class NonRecursivePersisterHelper {
   protected static Set<Id<ResourceId>> getInheritedAccessorResourceIds(SQLStrings sqlStrings,
                                                                        SQLConnection connection,
                                                                        Resource accessorResource) {
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

   protected static Set<Id<DomainId>> getDescendantDomainIdsOrderedByAscendingLevel(SQLStrings sqlStrings,
                                                                                    SQLConnection connection,
                                                                                    Id<DomainId> parentDomainId) {
      SQLStatement statement = null;
      Set<Id<DomainId>> allDomainIds = new LinkedHashSet<>();
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

   protected static Set<String> getDescendantDomainNames(SQLStrings sqlStrings,
                                                         SQLConnection connection,
                                                         String parentDomainName) {
      SQLStatement statement = null;
      Set<String> allDomainNames = new HashSet<>();
      allDomainNames.add(parentDomainName);
      Set<String> previousDomainNames = new HashSet<>(allDomainNames);

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_DirectDescendantResourceDomainName_BY_ResourceDomainName);

         while (!previousDomainNames.isEmpty()) {
            Set<String> newestDomainNames = new HashSet<>();

            for (String domainName : previousDomainNames) {
               statement.setString(1, domainName);
               SQLResult resultSet = statement.executeQuery();

               while (resultSet.next()) {
                  newestDomainNames.add(resultSet.getString("DomainName"));
               }
               resultSet.close();
            }
            allDomainNames.addAll(newestDomainNames);
            previousDomainNames = newestDomainNames;
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         Persister.closeStatement(statement);
      }

      return allDomainNames;
   }

   protected static Set<Id<DomainId>> getAncestorDomainIds(SQLStrings sqlStrings,
                                                           SQLConnection connection,
                                                           Id<DomainId> domainId) {
      SQLStatement statement = null;
      Set<Id<DomainId>> ancestorDomainIds = new HashSet<>();
      ancestorDomainIds.add(domainId);
      int previousSize = 0;

      try {
         statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_ParentResourceDomainName_BY_DomainID);
         Id<DomainId> parentDomainId = domainId;

         while (previousSize < ancestorDomainIds.size()) {
            previousSize = ancestorDomainIds.size();
            statement.setResourceDomainId(1, parentDomainId);
            SQLResult resultSet = statement.executeQuery();

            if (resultSet.next()) {
               parentDomainId = resultSet.getResourceDomainId("DomainId");
               ancestorDomainIds.add(parentDomainId);
            }
            resultSet.close();
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         Persister.closeStatement(statement);
      }

      return ancestorDomainIds;
   }
}
