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

public class RecursiveResourcePersister extends CommonResourcePersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public RecursiveResourcePersister(SQLProfile sqlProfile,
                                     SQLStrings sqlStrings) {
      super(sqlProfile, sqlStrings);
   }

   @Override
   public boolean isDomainEmpty(SQLConnection connection, Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResource_COUNTResourceID_BY_DomainID);
         statement.setResourceDomainId(1, resourceDomainId);
         resultSet = statement.executeQuery();

         if (!resultSet.next()) {
            throw new IllegalArgumentException("Could not read resource count for domain: " + resourceDomainId);
         }

         final int count = resultSet.getInteger("COUNTResourceID");

         resultSet.close();

         return count == 0;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }
}
