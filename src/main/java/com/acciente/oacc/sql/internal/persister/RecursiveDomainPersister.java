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
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class RecursiveDomainPersister extends CommonDomainPersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public RecursiveDomainPersister(SQLProfile sqlProfile,
                                   SQLStrings sqlStrings) {
      super(sqlProfile, sqlStrings);
   }

   @Override
   public Set<String> getResourceDomainNameDescendants(SQLConnection connection,
                                                       String resourceDomainName) {
      SQLStatement statement = null;

      try {
         Set<String> resourceDomainNameDescendants;

         statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_DescendantResourceDomainName_BY_ResourceDomainName);
         statement.setString(1, resourceDomainName);
         SQLResult resultSet = statement.executeQuery();

         resourceDomainNameDescendants = new HashSet<>();

         while (resultSet.next()) {
            resourceDomainNameDescendants.add(resultSet.getString("DomainName"));
         }

         return resourceDomainNameDescendants;
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
         // chose strategy to perform recursive delete based on sql profile
         if (sqlProfile.isRecursiveDeleteEnabled()) {
            // prepare the standard recursive delete statement of domain and its children
            statement = connection.prepareStatement(sqlStrings.SQL_removeInDomain_withDescendants_BY_DomainID);
            statement.setResourceDomainId(1, domainId);

            final int rowCount = statement.executeUpdate();

            if (rowCount < 1) {
               throw new IllegalStateException("Security table data update, 1 or more rows expected, got: " + rowCount);
            }
         }
         else {
            // DBMS doesn't support recursive deletion, so we have to remove domain's children first

            // get descendant domain Ids
            statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_DescendantResourceDomainID_BY_DomainID_ORDERBY_DomainLevel);
            statement.setResourceDomainId(1, domainId);
            SQLResult resultSet = statement.executeQuery();

            List<Id<DomainId>> descendantDomainIds = new ArrayList<>();

            while (resultSet.next()) {
               descendantDomainIds.add(resultSet.getResourceDomainId("DomainId"));
            }
            closeStatement(statement);

            // delete descendant domains one at a time, in reverse order of domainLevel, to preserve FK constraints
            statement = connection.prepareStatement(sqlStrings.SQL_removeInDomain_BY_DomainID);

            for (int i=descendantDomainIds.size()-1; i >= 0; i--) {
               statement.setResourceDomainId(1, descendantDomainIds.get(i));
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
