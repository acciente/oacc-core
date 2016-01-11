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
package com.acciente.oacc.helper;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class OACC_ResourceClass extends DbBase {
   private final Long   resourceClassID;
   private final String resourceClassName;
   private final Short  isAuthenticatable;
   private final Short  isUnauthenticatedCreateAllowed;

   private static String getQualifiedTableName(String schemaName) {
      return getSchemaAndTableNamePrefix(schemaName) + "ResourceClass";
   }

   private static String getPKColumnNames() {
      return "ResourceClassID";
   }

   OACC_ResourceClass(Builder builder) {
      resourceClassID = builder.resourceClassID;
      resourceClassName = builder.resourceClassName;
      isAuthenticatable = builder.isAuthenticatable;
      isUnauthenticatedCreateAllowed = builder.isUnauthenticatedCreateAllowed;
   }

   public Long getResourceClassID() {
      return resourceClassID;
   }

   public String getResourceClassName() {
      return resourceClassName;
   }

   public Short getIsAuthenticatable() {
      return isAuthenticatable;
   }

   public Short getIsUnauthenticatedCreateAllowed() {
      return isUnauthenticatedCreateAllowed;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      }
      if (o == null || getClass() != o.getClass()) {
         return false;
      }

      OACC_ResourceClass that = (OACC_ResourceClass) o;

      if (isAuthenticatable != null
          ? !isAuthenticatable.equals(that.isAuthenticatable)
          : that.isAuthenticatable != null) {
         return false;
      }
      if (isUnauthenticatedCreateAllowed != null
          ? !isUnauthenticatedCreateAllowed.equals(that.isUnauthenticatedCreateAllowed)
          : that.isUnauthenticatedCreateAllowed != null) {
         return false;
      }
      if (resourceClassID != null ? !resourceClassID.equals(that.resourceClassID) : that.resourceClassID != null) {
         return false;
      }
      if (resourceClassName != null
          ? !resourceClassName.equals(that.resourceClassName)
          : that.resourceClassName != null) {
         return false;
      }

      return true;
   }

   @Override
   public int hashCode() {
      int result = resourceClassID != null ? resourceClassID.hashCode() : 0;
      result = 31 * result + (resourceClassName != null ? resourceClassName.hashCode() : 0);
      result = 31 * result + (isAuthenticatable != null ? isAuthenticatable.hashCode() : 0);
      result = 31 * result + (isUnauthenticatedCreateAllowed != null ? isUnauthenticatedCreateAllowed.hashCode() : 0);
      return result;
   }

   @Override
   public String toString() {
      return "OACC_ResourceClass{" +
            "resourceClassID=" + resourceClassID +
            ", resourceClassName='" + resourceClassName + '\'' +
            ", isAuthenticatable=" + isAuthenticatable +
            ", isUnauthenticatedCreateAllowed=" + isUnauthenticatedCreateAllowed +
            '}';
   }

   public static class Builder {
      private Long   resourceClassID;
      private String resourceClassName;
      private Short  isAuthenticatable;
      private Short  isUnauthenticatedCreateAllowed;

      public Builder(Long resourceClassID) {
         this.resourceClassID = resourceClassID;
      }

      public Builder resourceClassName(String resourceClassName) {
         this.resourceClassName = resourceClassName;
         return this;
      }

      public Builder isAuthenticatable(Boolean authenticatable) {
         isAuthenticatable = authenticatable == null ? null : (short) (authenticatable ? 1 : 0);
         return this;
      }

      public Builder isUnauthenticatedCreateAllowed(Boolean unauthenticatedCreateAllowed) {
         isUnauthenticatedCreateAllowed = unauthenticatedCreateAllowed == null
                                          ? null
                                          : (short) (unauthenticatedCreateAllowed ? 1 : 0);
         return this;
      }

      public OACC_ResourceClass build() {
         return new OACC_ResourceClass(this);
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

      public static OACC_ResourceClass findByID(Connection con,
                                               String dbSchema,
                                               int resourceClassID) throws SQLException {
         try (PreparedStatement preparedStatement
                    = con.prepareStatement("SELECT * FROM " + getQualifiedTableName(dbSchema) + " WHERE ResourceClassID=?");
         ) {
            OACC_ResourceClass resourceClass = null;
            preparedStatement.setInt(1, resourceClassID);
            ResultSet resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
               resourceClass = getDB_ResourceClass(resultSet);
            }
            if (resultSet.next()) {
               throw new IllegalStateException("found multiple rows in " + getQualifiedTableName(dbSchema) + " for the same primary key");
            }

            return resourceClass;
         }
      }

      private static OACC_ResourceClass getDB_ResourceClass(ResultSet resultSet) throws SQLException {
         final Short isAuthenticatable = getShort(resultSet, "isAuthenticatable");
         final Short isUnauthenticatedCreateAllowed = getShort(resultSet, "isUnauthenticatedCreateAllowed");
         return new Builder(getLong(resultSet, "resourceClassID"))
               .resourceClassName(resultSet.getString("resourceClassName"))
               .isAuthenticatable(isAuthenticatable == null ? null : isAuthenticatable == 0 ? false : true)
               .isUnauthenticatedCreateAllowed(isUnauthenticatedCreateAllowed == null
                                               ? null
                                               : isUnauthenticatedCreateAllowed == 0 ? false : true)
               .build();
      }
   }
}
