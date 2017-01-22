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
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.Set;

public abstract class CommonDomainPersister extends Persister implements DomainPersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public CommonDomainPersister(SQLProfile sqlProfile,
                                SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public Id<DomainId> getResourceDomainId(SQLConnection connection,
                                           String resourceDomainName) {
      SQLStatement statement = null;

      if (resourceDomainName == null) {
         throw new IllegalArgumentException("Domain name must not be null");
      }

      try {
         Id<DomainId> resourceDomainId = null;

         statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_DomainID_BY_ResourceDomainName);
         statement.setString(1, resourceDomainName.trim());
         SQLResult resultSet = statement.executeQuery();

         if (resultSet.next()) {
            resourceDomainId = resultSet.getResourceDomainId("DomainId");
         }

         return resourceDomainId;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public String getResourceDomainNameByResourceId(SQLConnection connection,
                                                   Resource resource) {
      SQLStatement statement = null;

      try {
         String resourceDomainName = null;

         statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_ResourceDomainName_BY_ResourceID);
         statement.setResourceId(1, resource);
         SQLResult resultSet = statement.executeQuery();

         if (resultSet.next()) {
            resourceDomainName = resultSet.getString("DomainName");
         }

         if (resourceDomainName == null) {
            throw new IllegalArgumentException("Could not determine domain for resource: " + resource);
         }

         return resourceDomainName;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public abstract Set<String> getResourceDomainNameDescendants(SQLConnection connection,
                                                                String resourceDomainName);

   @Override
   public void addResourceDomain(SQLConnection connection,
                                 String resourceDomainName) {
      SQLStatement statement = null;

      try {
         // create the new root domain
         statement = connection.prepareStatement(sqlStrings.SQL_createInDomain_WITH_ResourceDomainName);
         statement.setString(1, resourceDomainName);
         assertOneRowInserted(statement.executeUpdate());
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void addResourceDomain(SQLConnection connection,
                                 String resourceDomainName,
                                 Id<DomainId> parentResourceDomainId) {
      SQLStatement statement = null;

      try {
         // create the new child domain
         statement = connection.prepareStatement(sqlStrings.SQL_createInDomain_WITH_ResourceDomainName_ParentDomainID);
         statement.setString(1, resourceDomainName);
         statement.setResourceDomainId(2, parentResourceDomainId);
         assertOneRowInserted(statement.executeUpdate());
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public abstract void deleteDomain(SQLConnection connection, Id<DomainId> domainId);
}
