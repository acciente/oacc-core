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
import com.acciente.oacc.encryptor.jasypt.JasyptPasswordEncryptor;
import com.acciente.oacc.encryptor.jasypt.LegacyJasyptPasswordEncryptor;
import com.acciente.oacc.sql.internal.SQLAccessControlContext;

import javax.sql.DataSource;
import java.sql.Connection;

/**
 * The factory that provides OACC's AccessControlContext implementation, which is backed by a database.
 */
public class SQLAccessControlContextFactory {
   /**
    * Creates an {@link AccessControlContext} instance backed by the specified database connection. A set of valid
    * OACC database tables are expected to reside in the specified schema. The dialect of SQL supported by the database
    * server for which the connection is provided is specified using the SQLProfile parameter. The access control
    * context returned by this method uses the built-in authentication provider that delegates all password encryption
    * and decryption to a {@link PasswordEncryptor} instance provided by
    * {@link LegacyJasyptPasswordEncryptor#newInstance()} -- therefore the instance returned by this method may
    * only be used when all existing resource passwords were encrypted using Jasypt. This method is deprecated, please
    * see the deprecation note below.
    *
    * @param connection a database connection with access to the required OACC tables
    * @param schemaName the name of the schema in the database containing the OACC tables
    * @param sqlProfile the database provider and dialect of SQL supported for the database server associated
    *                   with the connection provided
    * @return an {@link AccessControlContext} instance ready to receive API calls
    * @deprecated as of OACC v2.0.0-rc8, replaced by
    * {@link #getAccessControlContext(Connection, String, SQLProfile, PasswordEncryptor)} where the password encryptor
    * parameter is an instance of the new Jasypt password encryptor implementation
    * {@link JasyptPasswordEncryptor}.
    */
   @Deprecated
   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLProfile sqlProfile) {
      return SQLAccessControlContext.getAccessControlContext(connection,
                                                             schemaName,
                                                             sqlProfile,
                                                             LegacyJasyptPasswordEncryptor.newInstance());
   }

   /**
    * Creates an {@link AccessControlContext} instance backed by the specified database data source. A set of valid
    * OACC database tables are expected to reside in the specified schema. The dialect of SQL supported by the database
    * server for which the data source is provided is specified using the SQLProfile parameter. The access control
    * context returned by this method uses the built-in authentication provider that delegates all password encryption
    * and decryption to a {@link PasswordEncryptor} instance provided by
    * {@link LegacyJasyptPasswordEncryptor#newInstance()} -- therefore the instance returned by this method may
    * only be used when all existing resource passwords were encrypted using Jasypt. This method is deprecated, please
    * see the deprecation note below.
    *
    * @param dataSource a database data source with access to the required OACC tables
    * @param schemaName the name of the schema in the database containing the OACC tables
    * @param sqlProfile the database provider and dialect of SQL supported for the database server associated
    *                   with the connection provided
    * @return an {@link AccessControlContext} instance ready to receive API calls
    * @deprecated as of OACC v2.0.0-rc8, replaced by
    * {@link #getAccessControlContext(DataSource, String, SQLProfile, PasswordEncryptor)} where the password encryptor
    * parameter is an instance of the new Jasypt password encryptor implementation
    * {@link JasyptPasswordEncryptor}.
    */
   @Deprecated
   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLProfile sqlProfile) {
      return SQLAccessControlContext.getAccessControlContext(dataSource,
                                                             schemaName,
                                                             sqlProfile,
                                                             LegacyJasyptPasswordEncryptor.newInstance());
   }

   /**
    * Creates an {@link AccessControlContext} instance backed by the specified database connection. A set of valid
    * OACC database tables are expected to reside in the specified schema. The dialect of SQL supported by the database
    * server for which the connection is provided is specified using the SQLProfile parameter. The access control
    * context returned by this method uses the built-in authentication provider for resource authentication. The
    * built-in authentication provider delegates all password encryption and decryption to the {@link PasswordEncryptor}
    * instance provided -- therefore it is imperative that the {@link PasswordEncryptor} instance is able to decrypt
    * existing resource passwords.
    *
    * @param connection        a database connection with access to the required OACC tables
    * @param schemaName        the name of the schema in the database containing the OACC tables
    * @param sqlProfile        the database provider and dialect of SQL supported for the database server associated
    *                          with the connection provided
    * @param passwordEncryptor a {@link PasswordEncryptor} instance to which the built-in authentication provider
    *                          delegates all password encryption and decryption
    * @return an {@link AccessControlContext} instance ready to receive API calls
    */
   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLProfile sqlProfile,
                                                              PasswordEncryptor passwordEncryptor) {
      return SQLAccessControlContext.getAccessControlContext(connection,
                                                             schemaName,
                                                             sqlProfile,
                                                             passwordEncryptor);
   }

   /**
    * Creates an {@link AccessControlContext} instance backed by the specified database data source. A set of valid
    * OACC database tables are expected to reside in the specified schema. The dialect of SQL supported by the database
    * server for which the data source is provided is specified using the SQLProfile parameter. The access control
    * context returned by this method uses the built-in authentication provider for resource authentication. The
    * built-in authentication provider delegates all password encryption and decryption to the {@link PasswordEncryptor}
    * instance provided -- therefore it is important that the {@link PasswordEncryptor} instance is able to decrypt
    * existing resource passwords.
    *
    * @param dataSource        a database data source with access to the required OACC tables
    * @param schemaName        the name of the schema in the database containing the OACC tables
    * @param sqlProfile        the database provider and dialect of SQL supported for the database server associated
    *                          with the data source provided
    * @param passwordEncryptor a {@link PasswordEncryptor} instance to which the built-in authentication provider
    *                          delegates all password encryption and decryption
    * @return an {@link AccessControlContext} instance ready to receive API calls
    */
   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLProfile sqlProfile,
                                                              PasswordEncryptor passwordEncryptor) {
      return SQLAccessControlContext.getAccessControlContext(dataSource,
                                                             schemaName,
                                                             sqlProfile,
                                                             passwordEncryptor);
   }

   /**
    * Creates an {@link AccessControlContext} instance backed by the specified database connection. A set of valid
    * OACC database tables are expected to reside in the specified schema. The dialect of SQL supported by the database
    * server for which the connection is provided is specified using the SQLProfile parameter. The access control
    * context returned by this method delegates all resource authentication to the specified custom authentication
    * provider.
    *
    * @param connection             a database connection with access to the required OACC tables
    * @param schemaName             the name of the schema in the database containing the OACC tables
    * @param sqlProfile             the database provider and dialect of SQL supported for the database server associated
    *                               with the connection provided
    * @param authenticationProvider an {@link AuthenticationProvider} instance to which all resource authentication is
    *                               delegated
    * @return an {@link AccessControlContext} instance ready to receive API calls
    */
   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLProfile sqlProfile,
                                                              AuthenticationProvider authenticationProvider) {
      return SQLAccessControlContext.getAccessControlContext(connection,
                                                             schemaName,
                                                             sqlProfile,
                                                             authenticationProvider);
   }

   /**
    * Creates an {@link AccessControlContext} instance backed by the specified database data source. A set of valid
    * OACC database tables are expected to reside in the specified schema. The dialect of SQL supported by the database
    * server for which the data source is provided is specified using the SQLProfile parameter. The access control
    * context returned by this method delegates all resource authentication to the specified custom authentication
    * provider.
    *
    * @param dataSource             a database data source with access to the required OACC tables
    * @param schemaName             the name of the schema in the database containing the OACC tables
    * @param sqlProfile             the database provider and dialect of SQL supported for the database server associated
    *                               with the connection provided
    * @param authenticationProvider an {@link AuthenticationProvider} instance to which all resource authentication is
    *                               delegated
    * @return an {@link AccessControlContext} instance ready to receive API calls
    */
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
    * @deprecated As of v2.0.0-rc.6; no replacement method necessary because unserializable fields are now marked as transient
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
    * @param connection           the database connection to be reset on the accessControlContext
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
    * @param dataSource           the database dataSource to be reset on the accessControlContext
    */
   public static void postDeserialize(AccessControlContext accessControlContext, DataSource dataSource) {
      SQLAccessControlContext.postDeserialize(accessControlContext, dataSource);
   }
}