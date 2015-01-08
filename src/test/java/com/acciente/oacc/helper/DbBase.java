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
package com.acciente.oacc.helper;

import java.sql.ResultSet;
import java.sql.SQLException;

public class DbBase {
   protected static String getSchemaAndTableNamePrefix(String schemaName) {
      return schemaName != null ? schemaName + ".OAC_" : "OAC_";
   }

   protected static Long getLong(ResultSet resultSet, String columnLabel) throws SQLException {
      final long longValue = resultSet.getLong(columnLabel);
      if (resultSet.wasNull()) {
         return null;
      }
      return longValue;
   }

   protected static Short getShort(ResultSet resultSet, String columnLabel) throws SQLException {
      final short shortValue = resultSet.getShort(columnLabel);
      if (resultSet.wasNull()) {
         return null;
      }
      return shortValue;
   }
}
