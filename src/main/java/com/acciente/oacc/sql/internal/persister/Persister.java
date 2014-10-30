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

import java.sql.SQLException;

/**
 * Base class for persisters
 */
public abstract class Persister {
   protected static void closeStatement(SQLStatement statement)
         throws AccessControlException {
      try {
         if (statement != null) {
            statement.close();
         }
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
   }

   // data verification helpers

   protected void assertOneRowInserted(int rowCount) throws AccessControlException {
      if (rowCount != 1) {
         throw new AccessControlException("Security table data insert, 1 row expected, got: " + rowCount);
      }
   }

   protected void assertOneRowUpdated(int rowCount) throws AccessControlException {
      if (rowCount != 1) {
         throw new AccessControlException("Security table data update, 1 row expected, got: " + rowCount);
      }
   }
}
