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
package com.acciente.oacc.sql;

import com.acciente.oacc.AccessControlContext;
import com.acciente.oacc.AuthenticationProvider;
import com.acciente.oacc.sql.internal.SQLAccessControlContext;

import javax.sql.DataSource;
import java.sql.Connection;

public class SQLAccessControlContextFactory {
   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLType sqlType) {
      return SQLAccessControlContext.getAccessControlContext(connection,
                                                             schemaName,
                                                             sqlType);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLType sqlType) {
      return SQLAccessControlContext.getAccessControlContext(dataSource,
                                                             schemaName,
                                                             sqlType);
   }

   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLType sqlType,
                                                              AuthenticationProvider authenticationProvider) {
      return SQLAccessControlContext.getAccessControlContext(connection,
                                                             schemaName,
                                                             sqlType,
                                                             authenticationProvider);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLType sqlType,
                                                              AuthenticationProvider authenticationProvider) {
      return SQLAccessControlContext.getAccessControlContext(dataSource,
                                                             schemaName,
                                                             sqlType,
                                                             authenticationProvider);
   }

   public static void preSerialize(AccessControlContext accessControlContext) {
      SQLAccessControlContext.preSerialize(accessControlContext);
   }

   public static void postDeserialize(AccessControlContext accessControlContext, Connection connection) {
      SQLAccessControlContext.postDeserialize(accessControlContext, connection);
   }

   public static void postDeserialize(AccessControlContext accessControlContext, DataSource dataSource) {
      SQLAccessControlContext.postDeserialize(accessControlContext, dataSource);
   }
}
