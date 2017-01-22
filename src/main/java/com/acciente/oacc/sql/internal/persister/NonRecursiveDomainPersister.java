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

import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class NonRecursiveDomainPersister extends CommonDomainPersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public NonRecursiveDomainPersister(SQLProfile sqlProfile,
                                      SQLStrings sqlStrings) {
      super(sqlProfile, sqlStrings);
   }

   @Override
   public Set<String> getResourceDomainNameDescendants(SQLConnection connection,
                                                       String resourceDomainName) {
      SQLStatement statement = null;

      try {
         // verify the domain
         if (getResourceDomainId(connection, resourceDomainName) == null) {
            return Collections.emptySet();
         }

         Set<String> allDescendantDomainNames = new HashSet<>();
         Set<Id<DomainId>> previousDescendantDomainIds = new HashSet<>();

         allDescendantDomainNames.add(resourceDomainName);

         // find first-level descendants (excluding the requested root domain)
         statement = connection
               .prepareStatement(sqlStrings.SQL_findInDomain_DirectDescendantResourceDomainName_BY_ResourceDomainName);
         statement.setString(1, resourceDomainName);
         SQLResult resultSet = statement.executeQuery();

         while (resultSet.next()) {
            allDescendantDomainNames.add(resultSet.getString("DomainName"));
            previousDescendantDomainIds.add(resultSet.getResourceDomainId("DomainId"));
         }
         statement.close();

         // find second-level and higher descendants, if necessary
         if (allDescendantDomainNames.size() > 1) {
            Set<Id<DomainId>> newestDescendantDomainIds = new HashSet<>();
            int prevTotalOfDescendantDomains = 1;
            while (allDescendantDomainNames.size() > prevTotalOfDescendantDomains) {
               prevTotalOfDescendantDomains = allDescendantDomainNames.size();

               for (Id<DomainId> descendantDomainId : previousDescendantDomainIds) {
                  statement = connection
                        .prepareStatement(sqlStrings.SQL_findInDomain_DirectDescendantResourceDomainName_BY_DomainID);
                  statement.setResourceDomainId(1, descendantDomainId);
                  resultSet = statement.executeQuery();

                  while (resultSet.next()) {
                     allDescendantDomainNames.add(resultSet.getString("DomainName"));
                     newestDescendantDomainIds.add(resultSet.getResourceDomainId("DomainId"));
                  }
                  statement.close();
               }
               previousDescendantDomainIds = newestDescendantDomainIds;
            }
         }

         return allDescendantDomainNames;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void deleteDomain(SQLConnection connection,
                            Id<DomainId> domainId) {
      SQLStatement statement = null;

      try {
         // get descendant domain Ids
         List<Id<DomainId>> descendantDomainIds
               = new ArrayList<>(NonRecursivePersisterHelper.getDescendantDomainIdsOrderedByAscendingLevel(sqlStrings,
                                                                                                           connection,
                                                                                                           domainId));

         // delete descendant domains one at a time, in reverse order of domainLevel, to preserve FK constraints
         statement = connection.prepareStatement(sqlStrings.SQL_removeInDomain_BY_DomainID);

         for (int i = descendantDomainIds.size() - 1; i >= 0; i--) {
            statement.setResourceDomainId(1, descendantDomainIds.get(i));
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
