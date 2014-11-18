package com.acciente.oacc.sql.internal;

import com.acciente.oacc.AccessControlException;
import com.acciente.oacc.AuthenticationProvider;
import com.acciente.oacc.Credentials;
import com.acciente.oacc.PasswordCredentials;
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.SQLDialect;
import com.acciente.oacc.sql.internal.persister.ResourcePasswordPersister;
import com.acciente.oacc.sql.internal.persister.SQLConnection;
import com.acciente.oacc.sql.internal.persister.SQLPasswordStrings;

import javax.sql.DataSource;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.SQLException;

public class SQLPasswordAuthenticationProvider implements AuthenticationProvider, Serializable {
   // services
   private DataSource                 dataSource;
   private Connection                 connection;
   private CleanablePasswordEncryptor passwordEncryptor;

   // persisters
   private final ResourcePasswordPersister resourcePasswordPersister;

   // protected constructors/methods
   protected SQLPasswordAuthenticationProvider(Connection connection,
                                             String schemaName,
                                             SQLDialect sqlDialect) throws AccessControlException {
      this(schemaName, sqlDialect);
      this.connection = connection;
   }

   protected SQLPasswordAuthenticationProvider(DataSource dataSource,
                                             String schemaName,
                                             SQLDialect sqlDialect) throws AccessControlException {
      this(schemaName, sqlDialect);
      this.dataSource = dataSource;
   }

   private SQLPasswordAuthenticationProvider(String schemaName, SQLDialect sqlDialect)
         throws AccessControlException {
      this.passwordEncryptor = new StrongCleanablePasswordEncryptor();

      // generate all the SQLs the persisters need based on the database dialect
      SQLPasswordStrings sqlPasswordStrings = SQLPasswordStrings.getSQLPasswordStrings(schemaName);

      // setup persisters
      resourcePasswordPersister = new ResourcePasswordPersister(sqlPasswordStrings);
   }

   protected void preSerialize() {
      this.dataSource = null;
      this.connection = null;
   }

   protected void postDeserialize(DataSource dataSource) {
      this.dataSource = dataSource;
      this.connection = null;
   }

   protected void postDeserialize(Connection connection) {
      this.dataSource = null;
      this.connection = connection;
   }

   @Override
   public void authenticate(Resource resource, Credentials credentials) throws AccessControlException {
      assertSupportedCredentials(credentials);

      final PasswordCredentials passwordCredentials = ((PasswordCredentials) credentials);

      if (passwordCredentials.getPassword() == null) {
         throw new AccessControlException("Password required, none specified");
      }

      SQLConnection connection = null;
      try {
         connection = getConnection();

         __authenticate(connection, resource, passwordCredentials.getPassword());
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void authenticate(Resource resource) throws AccessControlException {
      throw new AccessControlException("The built-in password authentication provider does not support authentication without credentials");
   }

   private void __authenticate(SQLConnection connection, Resource resource, char[] password)
         throws AccessControlException, SQLException {
      // first locate the resource
      final String encryptedBoundPassword = resourcePasswordPersister.getEncryptedBoundPasswordByResourceId(connection, resource);

      char[] plainBoundPassword = null;
      try {
         plainBoundPassword = PasswordUtils.computeBoundPassword(resource, password);

         if (!passwordEncryptor.checkPassword(plainBoundPassword, encryptedBoundPassword)) {
            throw new AccessControlException("Invalid password for " + resource, true);
         }
      }
      finally {
         PasswordUtils.cleanPassword(plainBoundPassword);
      }
   }

   @Override
   public void validateCredentials(Credentials credentials) throws AccessControlException {
      assertSupportedCredentials(credentials);

      final char[] password = ((PasswordCredentials) credentials).getPassword();

      if (password == null) {
         throw new AccessControlException("Password required, none specified");
      }

      if (password.length == 0) {
         throw new AccessControlException("Password cannot be zero length");
      }

      if (isBlank(password)) {
         throw new AccessControlException("Password cannot be blank");
      }
   }

   @Override
   public void setCredentials(Resource resource, Credentials credentials) throws AccessControlException {
      assertSupportedCredentials(credentials);

      final PasswordCredentials passwordCredentials = ((PasswordCredentials) credentials);

      SQLConnection connection = null;
      try {
         connection = getConnection();

         __setResourcePassword(connection,
                               resource,
                               passwordCredentials.getPassword());
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __setResourcePassword(SQLConnection connection, Resource resource, char[] newPassword)
         throws AccessControlException, SQLException {
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

   private void assertSupportedCredentials(Credentials credentials) throws AccessControlException {
      if (!(credentials instanceof PasswordCredentials)) {
         throw new AccessControlException("Unsupported credentials implementation: " + credentials.getClass());
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

   private SQLConnection getConnection() throws SQLException, AccessControlException {
      if (dataSource != null) {
         return new SQLConnection(dataSource.getConnection());
      }
      else if (connection != null) {
         return new SQLConnection(connection);
      }
      else {
         throw new AccessControlException("Not initialized! No data source or connection, perhaps missing call to postDeserialize()?");
      }
   }

   private void closeConnection(SQLConnection connection) throws AccessControlException {
      // only close the connection if we got it from a pool, otherwise just leave the connection open
      if (dataSource != null) {
         if (connection != null) {
            try {
               connection.close();
            }
            catch (SQLException e) {
               throw new AccessControlException(e);
            }
         }
      }
   }

}
