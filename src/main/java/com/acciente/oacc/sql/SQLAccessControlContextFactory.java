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
package com.acciente.oacc.sql;

import com.acciente.oacc.AccessControlContext;
import com.acciente.oacc.AuthenticationProvider;
import com.acciente.oacc.encryptor.PasswordEncryptor;
import com.acciente.oacc.sql.internal.SQLAccessControlContext;

import javax.sql.DataSource;
import java.sql.Connection;

/**
 * The factory that provides OACC's AccessControlContext implementation, which is backed by a database.
 */
public class SQLAccessControlContextFactory {
   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLProfile sqlProfile,
                                                              PasswordEncryptor passwordEncryptor) {
      return SQLAccessControlContext.getAccessControlContext(connection,
                                                             schemaName,
                                                             sqlProfile,
                                                             passwordEncryptor);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLProfile sqlProfile,
                                                              PasswordEncryptor passwordEncryptor) {
      return SQLAccessControlContext.getAccessControlContext(dataSource,
                                                             schemaName,
                                                             sqlProfile,
                                                             passwordEncryptor);
   }

   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLProfile sqlProfile,
                                                              AuthenticationProvider authenticationProvider) {
      return SQLAccessControlContext.getAccessControlContext(connection,
                                                             schemaName,
                                                             sqlProfile,
                                                             authenticationProvider);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLProfile sqlProfile,
                                                              AuthenticationProvider authenticationProvider) {
      return SQLAccessControlContext.getAccessControlContext(dataSource,
                                                             schemaName,
                                                             sqlProfile,
                                                             authenticationProvider);
   }

   /**
    * @deprecated  As of v2.0.0-rc.6; no replacement method necessary because unserializable fields are now marked as transient
    */
   @Deprecated
   public static void preSerialize(AccessControlContext accessControlContext) {
   }

   /**
    * Re-initializes the specified deserialized accessControlContext with the specified connection.
    * <p/>
    * This method is only intended to be called after the specified accessControlContext was successfully
    * deserialized, in order to reset a transient connection to a database that was not serialized. If the
    * method is called when a data source or connection has already been initialized, the method may pass
    * through an IllegalStateException from the accessControlContext.
    *
    * @param accessControlContext the accessControlContext on which to reset the database connection
    * @param connection the database connection to be reset on the accessControlContext
    */
   public static void postDeserialize(AccessControlContext accessControlContext, Connection connection) {
      SQLAccessControlContext.postDeserialize(accessControlContext, connection);
   }

   /**
    * Re-initializes the specified deserialized accessControlContext with the specified data source.
    * <p/>
    * This method is only intended to be called after the specified accessControlContext was successfully
    * deserialized, in order to reset a transient dataSource to a database that was not serialized. If the
    * method is called when a data source or connection has already been initialized, the method may pass
    * through an IllegalStateException from the accessControlContext.
    *
    * @param accessControlContext the accessControlContext on which to reset the database connection
    * @param dataSource the database dataSource to be reset on the accessControlContext
    */
   public static void postDeserialize(AccessControlContext accessControlContext, DataSource dataSource) {
      SQLAccessControlContext.postDeserialize(accessControlContext, dataSource);
   }
}