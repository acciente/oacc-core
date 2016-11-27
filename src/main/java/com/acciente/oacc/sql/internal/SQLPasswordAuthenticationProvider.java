/*
 * Copyright 2009-2016, Acciente LLC
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
package com.acciente.oacc.sql.internal;

import com.acciente.oacc.AuthenticationProvider;
import com.acciente.oacc.Credentials;
import com.acciente.oacc.IncorrectCredentialsException;
import com.acciente.oacc.InvalidCredentialsException;
import com.acciente.oacc.PasswordCredentials;
import com.acciente.oacc.Resource;
import com.acciente.oacc.UnsupportedCredentialsException;
import com.acciente.oacc.sql.SQLDialect;
import com.acciente.oacc.sql.internal.encryptor.PasswordEncryptor;
import com.acciente.oacc.sql.internal.encryptor.JasyptPasswordEncryptor;
import com.acciente.oacc.sql.internal.persister.ResourcePasswordPersister;
import com.acciente.oacc.sql.internal.persister.SQLConnection;
import com.acciente.oacc.sql.internal.persister.SQLPasswordStrings;

import javax.sql.DataSource;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.SQLException;

public class SQLPasswordAuthenticationProvider implements AuthenticationProvider, Serializable {
   private static final long serialVersionUID = 1L;

   // services
   private transient DataSource           dataSource;
   private transient Connection           connection;
   private transient PasswordEncryptor    passwordEncryptor;

   // persisters
   private final ResourcePasswordPersister resourcePasswordPersister;

   // protected constructors/methods
   protected SQLPasswordAuthenticationProvider(Connection connection,
                                               String schemaName,
                                               SQLDialect sqlDialect) {
      this(schemaName, sqlDialect);
      this.connection = connection;
   }

   protected SQLPasswordAuthenticationProvider(DataSource dataSource,
                                               String schemaName,
                                               SQLDialect sqlDialect) {
      this(schemaName, sqlDialect);
      this.dataSource = dataSource;
   }

   private SQLPasswordAuthenticationProvider(String schemaName, SQLDialect sqlDialect) {
      this.passwordEncryptor = new JasyptPasswordEncryptor();

      // generate all the SQLs the persisters need based on the database dialect
      SQLPasswordStrings sqlPasswordStrings = SQLPasswordStrings.getSQLPasswordStrings(schemaName);

      // setup persisters
      resourcePasswordPersister = new ResourcePasswordPersister(sqlPasswordStrings);
   }

   /**
    * @deprecated  As of v2.0.0-rc.6; no replacement method necessary because unserializable fields are now marked as transient
    */
   @Deprecated
   protected void preSerialize() {
   }

   /**
    * Re-initializes the transient data source after deserialization.
    * <p/>
    * This method is only intended to be called after successful deserialization, in order to reset
    * a transient data source to a database that was not serialized. If the method is called when a
    * data source or connection has already been initialized, the method will throw an IllegalStateException.
    *
    * @param dataSource   the database dataSource to be reset
    * @throws IllegalStateException if a dataSource or connection is already set
    */
   protected void postDeserialize(DataSource dataSource) {
      if (this.dataSource != null || this.connection != null) {
         throw new IllegalStateException("Cannot re-initialize an already initialized SQLPasswordAuthenticationProvider");
      }
      this.dataSource = dataSource;
      this.connection = null;
   }

   /**
    * Re-initializes the transient connection after deserialization.
    * <p/>
    * This method is only intended to be called after successful deserialization, in order to reset
    * a transient connection to a database that was not serialized. If the method is called when a
    * data source or connection has already been initialized, the method will throw an IllegalStateException.
    *
    * @param connection   the database connection to be reset
    * @throws IllegalStateException if a dataSource or connection is already set
    */
   protected void postDeserialize(Connection connection) {
      if (this.dataSource != null || this.connection != null) {
         throw new IllegalStateException("Cannot re-initialize an already initialized SQLPasswordAuthenticationProvider");
      }
      this.dataSource = null;
      this.connection = connection;
   }

   /*
    * Deserializes the object from the stream using the default method and re-initializes the transient passwordEncryptor
    * field. The remaining transient fields (dataSource and connection) need to be set after deserialization by calling
    * one of the postDeserialize() methods.
    */
   private void readObject(ObjectInputStream objectInputStream) throws ClassNotFoundException, IOException {
      // perform the default de-serialization first
      objectInputStream.defaultReadObject();

      // restore transient field
      passwordEncryptor = new JasyptPasswordEncryptor();

      // the other transient fields have to be set with a subsequent call to postDeserialize()
   }

   @Override
   public void authenticate(Resource resource, Credentials credentials) {
      assertCredentialSpecified(credentials);
      assertSupportedCredentials(credentials);

      final PasswordCredentials passwordCredentials = ((PasswordCredentials) credentials);

      if (passwordCredentials.getPassword() == null) {
         throw new InvalidCredentialsException("Password required, none specified");
      }

      SQLConnection connection = null;
      try {
         connection = getConnection();

         __authenticate(connection, resource, passwordCredentials.getPassword());
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void authenticate(Resource resource) {
      throw new UnsupportedOperationException("The built-in password authentication provider does not support authentication without credentials");
   }

   private void __authenticate(SQLConnection connection, Resource resource, char[] password) {
      // first locate the resource
      final String encryptedBoundPassword = resourcePasswordPersister.getEncryptedBoundPasswordByResourceId(connection, resource);

      char[] plainBoundPassword = null;
      try {
         plainBoundPassword = PasswordUtils.computeBoundPassword(resource, password);

         if (!passwordEncryptor.checkPassword(plainBoundPassword, encryptedBoundPassword)) {
            throw new IncorrectCredentialsException("Invalid password for resource " + resource);
         }
      }
      finally {
         PasswordUtils.cleanPassword(plainBoundPassword);
      }
   }

   @Override
   public void validateCredentials(String resourceClassName, String domainName, Credentials credentials) {
      if (credentials == null) {
         // instead of a NullPointerException we explicitly throw the InvalidCredentialsException
         // to distinguish from a programming error the indication that this implementation
         // does not support null credentials
         throw new InvalidCredentialsException("Credentials required, none specified");
      }

      assertSupportedCredentials(credentials);

      final char[] password = ((PasswordCredentials) credentials).getPassword();

      if (password == null) {
         throw new InvalidCredentialsException("Password required, none specified");
      }

      if (password.length == 0) {
         throw new InvalidCredentialsException("Password cannot be zero length");
      }

      if (isBlank(password)) {
         throw new InvalidCredentialsException("Password cannot be blank");
      }
   }

   @Override
   public void setCredentials(Resource resource, Credentials credentials) {
      assertCredentialSpecified(credentials);
      assertSupportedCredentials(credentials);

      final PasswordCredentials passwordCredentials = ((PasswordCredentials) credentials);

      SQLConnection connection = null;
      try {
         connection = getConnection();

         __setResourcePassword(connection,
                               resource,
                               passwordCredentials.getPassword());
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void deleteCredentials(Resource resource) {
      SQLConnection connection = null;
      try {
         connection = getConnection();

         resourcePasswordPersister.removeEncryptedBoundPasswordByResourceId(connection, resource);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __setResourcePassword(SQLConnection connection, Resource resource, char[] newPassword) {
      char[] newBoundPassword = null;
      try {
         newBoundPassword = PasswordUtils.computeBoundPassword(resource, newPassword);
         final String newEncryptedBoundPassword = passwordEncryptor.encryptPassword(newBoundPassword);
         resourcePasswordPersister.setEncryptedBoundPasswordByResourceId(connection,
                                                                         resource,
                                                                         newEncryptedBoundPassword);
      }
      finally {
         PasswordUtils.cleanPassword(newBoundPassword);
      }
   }

   private void assertCredentialSpecified(Credentials credentials) {
      if (credentials == null) {
         throw new NullPointerException("Credentials required, none specified");
      }
   }

   private void assertSupportedCredentials(Credentials credentials) {
      if (!(credentials instanceof PasswordCredentials)) {
         throw new UnsupportedCredentialsException(credentials.getClass());
      }
   }

   private boolean isBlank(char[] charArray) {
      for (char c : charArray) {
         if (!Character.isWhitespace(c)) {
            return false;
         }
      }
      return true;
   }

   // private connection management helper methods

   private SQLConnection getConnection() {
      if (dataSource != null) {
         try {
            return new SQLConnection(dataSource.getConnection());
         }
         catch (SQLException e) {
            throw new RuntimeException(e);
         }
      }
      else if (connection != null) {
         return new SQLConnection(connection);
      }
      else {
         throw new IllegalStateException("Not initialized! No data source or connection - don't forget to re-initialize after deserialization!");
      }
   }

   private void closeConnection(SQLConnection connection) {
      // only close the connection if we got it from a pool, otherwise just leave the connection open
      if (dataSource != null) {
         if (connection != null) {
            try {
               connection.close();
            }
            catch (SQLException e) {
               throw new RuntimeException(e);
            }
         }
      }
   }

}
