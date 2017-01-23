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
package com.acciente.oacc.helper;

import com.acciente.oacc.Resources;
import com.acciente.oacc.encryptor.PasswordEncryptor;
import com.acciente.oacc.sql.internal.PasswordUtils;
import com.acciente.oacc.encryptor.jasypt.JasyptPasswordEncryptor;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class OACC_ResourcePassword extends DbBase {
   private final Long   resourceID;
   private final String password;

   private final char[] password_plaintext;

   private static final PasswordEncryptor __passwordEncryptor = JasyptPasswordEncryptor.getPasswordEncryptor();

   OACC_ResourcePassword(Builder builder) {
      resourceID = builder.resourceID;
      password = builder.password;

      password_plaintext = builder.password_plaintext;
   }

   public static String getQualifiedTableName(String schemaName) {
      return getSchemaAndTableNamePrefix(schemaName) + "ResourcePassword";
   }

   public static String getPKColumnNames() {
      return "ResourceID";
   }

   public Long getResourceID() {
      return resourceID;
   }

   public String getPassword() {
      return password;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o)
         return true;
      if (o == null || getClass() != o.getClass())
         return false;

      OACC_ResourcePassword that = (OACC_ResourcePassword) o;

      if (resourceID != null ? !resourceID.equals(that.resourceID) : that.resourceID != null) return false;

      // comparing "passwords" (in either plaintext or digest form)
      // Note: the db only stores a digest, and comparing two digests against each other provides no information
      if (password_plaintext != null && that.password_plaintext != null) {
         if (!password_plaintext.equals(that.password_plaintext)) return false;
      }
      else {
         if (password_plaintext == null && that.password_plaintext == null) {
            if (password != null || that.password != null) return false;
         }

         if (password_plaintext != null) {
            if (that.password == null || !__passwordEncryptor.checkPassword(PasswordUtils.computeBoundPassword(Resources.getInstance(
                  resourceID), password_plaintext), that.password))
               return false;
         }
         else if (that.password_plaintext != null) {
            if (password == null || !__passwordEncryptor.checkPassword(PasswordUtils.computeBoundPassword(Resources.getInstance(
                  that.resourceID), that.password_plaintext), password))
               return false;
         }
      }

      return true;
   }

   @Override
   public int hashCode() {
      int result = resourceID != null ? resourceID.hashCode() : 0;
      return result;
   }

   @Override
   public String toString() {
      return "OACC_Resource{" +
            "resourceID=" + resourceID +
            ", password='" + password + '\'' +
            ", password_plaintext='" + password_plaintext + '\'' +
            '}';
   }

   public static class Builder {
      private Long   resourceID;
      private String password;

      private char[] password_plaintext;

      public Builder(Long resourceID) {
         this.resourceID = resourceID;
      }

      public Builder password(String password) {
         this.password = password;
         return this;
      }

      public Builder password_plaintext(char[] plaintext) {
         this.password_plaintext = plaintext;
         return this;
      }

      public OACC_ResourcePassword build() {
         return new OACC_ResourcePassword(this);
      }
   }

   public static class Finder {
      public static int getNumberOfRows(Connection con, String schemaName) throws SQLException {

         try (PreparedStatement preparedStatement
                    = con.prepareStatement("SELECT COUNT(*) FROM (SELECT DISTINCT " + getPKColumnNames() + " FROM " + getQualifiedTableName(schemaName) + ") T");
         ) {
            ResultSet resultSet = preparedStatement.executeQuery();
            resultSet.next();
            return resultSet.getInt(1);
         }
      }

      public static OACC_ResourcePassword findByID(Connection con, String dbSchema, int resourceID) throws SQLException {
         try (PreparedStatement preparedStatement
                    = con.prepareStatement("SELECT * FROM " + getQualifiedTableName(dbSchema) + " WHERE ResourceID=?");
         ) {
            OACC_ResourcePassword resource = null;
            preparedStatement.setInt(1, resourceID);
            ResultSet resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
               resource = getDB_Resource(resultSet);
            }
            if (resultSet.next()) {
               throw new IllegalStateException("found multiple rows in " + getQualifiedTableName(dbSchema) + " for the same primary key");
            }

            return resource;
         }
      }

      private static OACC_ResourcePassword getDB_Resource(ResultSet resultSet) throws SQLException {
         return new Builder(getLong(resultSet, "resourceID"))
               .password(resultSet.getString("password"))
               .build();
      }
   }
}
