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
package com.acciente.oacc.helper;

import com.acciente.oacc.sql.internal.PasswordUtils;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class OACC_Resource extends DbBase {
   private final Long   resourceID;
   private final Long   resourceClassID;
   private final String password;
   private final Long   domainID;

   private final String password_plaintext;

   private static final PasswordEncryptor __passwordEncryptor = new StrongPasswordEncryptor();

   OACC_Resource(Builder builder) {
      resourceID = builder.resourceID;
      resourceClassID = builder.resourceClassID;
      password = builder.password;
      domainID = builder.domainID;

      password_plaintext = builder.password_plaintext;
   }

   public static String getQualifiedTableName(String schemaName) {
      return getSchemaAndTableNamePrefix(schemaName) + "Resource";
   }

   public static String getPKColumnNames() {
      return "ResourceID";
   }

   public Long getResourceID() {
      return resourceID;
   }

   public Long getResourceClassID() {
      return resourceClassID;
   }

   public String getPassword() {
      return password;
   }

   public Long getDomainID() {
      return domainID;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;

      OACC_Resource that = (OACC_Resource) o;

      if (resourceClassID != null ? !resourceClassID.equals(that.resourceClassID) : that.resourceClassID != null)
         return false;
      if (domainID != null ? !domainID.equals(that.domainID) : that.domainID != null)
         return false;
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
            if (that.password == null || !__passwordEncryptor.checkPassword(PasswordUtils.computeBoundPassword(resourceID, password_plaintext), that.password))
               return false;
         }
         else if (that.password_plaintext != null) {
            if (password == null || !__passwordEncryptor.checkPassword(PasswordUtils.computeBoundPassword(that.resourceID, that.password_plaintext), password))
               return false;
         }
      }

      return true;
   }

   @Override
   public int hashCode() {
      int result = resourceID != null ? resourceID.hashCode() : 0;
      result = 31 * result + (resourceClassID != null ? resourceClassID.hashCode() : 0);
      // don't include password in hashCode calculation!
      result = 31 * result + (domainID != null ? domainID.hashCode() : 0);
      return result;
   }

   @Override
   public String toString() {
      return "OACC_Resource{" +
            "resourceID=" + resourceID +
            ", resourceClassID=" + resourceClassID +
            ", password='" + password + '\'' +
            ", domainID=" + domainID +
            ", password_plaintext='" + password_plaintext + '\'' +
            '}';
   }

   public static class Builder {
      private Long resourceID;
      private Long resourceClassID;
      private String password;
      private Long domainID;

      private String password_plaintext;

      public Builder(Long resourceID) {
         this.resourceID = resourceID;
      }

      public Builder resourceClassID(Long resourceClassID) {
         this.resourceClassID = resourceClassID;
         return this;
      }

      public Builder password(String password) {
         this.password = password;
         return this;
      }

      public Builder domainID(Long domainID) {
         this.domainID = domainID;
         return this;
      }

      public Builder password_plaintext(String plaintext) {
         this.password_plaintext = plaintext;
         return this;
      }

      public OACC_Resource build() {
         return new OACC_Resource(this);
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

      public static OACC_Resource findByID(Connection con, String dbSchema, int resourceID) throws SQLException {
         try (PreparedStatement preparedStatement
                    = con.prepareStatement("SELECT * FROM " + getQualifiedTableName(dbSchema) + " WHERE ResourceID=?");
         ) {
            OACC_Resource resource = null;
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

      private static OACC_Resource getDB_Resource(ResultSet resultSet) throws SQLException {
         return new Builder(getLong(resultSet, "resourceID"))
               .resourceClassID(getLong(resultSet, "resourceClassID"))
               .domainID(getLong(resultSet, "domainID"))
               .password(resultSet.getString("password"))
               .build();
      }
   }
}
