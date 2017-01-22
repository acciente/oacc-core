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

import java.sql.Connection;
import java.sql.SQLException;

public class SQLConnection {
   private final Connection connection;

   public SQLConnection(Connection connection) {
      this.connection = connection;
   }

   public SQLStatement prepareStatement(String sql) throws SQLException {
      return new SQLStatement(connection.prepareStatement(sql));
   }

   public SQLStatement prepareStatement(String sql, String[] generatedKeyColumns) throws SQLException {
      return new SQLStatement(connection.prepareStatement(sql, generatedKeyColumns));
   }

   public void close() throws SQLException {
      this.connection.close();
   }
}
