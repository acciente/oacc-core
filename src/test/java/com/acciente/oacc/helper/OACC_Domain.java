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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OACC_Domain extends DbBase {
   private final Long   domainID;
   private final String domainName;
   private final Long   parentDomainID;

   private static String getQualifiedTableName(String schemaName) {
      return getSchemaAndTableNamePrefix(schemaName) + "Domain";
   }

   private static String getPKColumnNames() {
      return "DomainID";
   }

   OACC_Domain(Builder builder) {
      domainID = builder.domainID;
      domainName = builder.domainName;
      parentDomainID = builder.parentDomainID;
   }

   public Long getDomainID() {
      return domainID;
   }

   public String getDomainName() {
      return domainName;
   }

   public Long getParentDomainID() {
      return parentDomainID;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      }
      if (o == null || getClass() != o.getClass()) {
         return false;
      }

      OACC_Domain that = (OACC_Domain) o;

      if (parentDomainID != null
          ? !parentDomainID.equals(that.parentDomainID)
          : that.parentDomainID != null) {
         return false;
      }
      if (domainID != null ? !domainID.equals(that.domainID) : that.domainID != null) {
         return false;
      }
      if (domainName != null
          ? !domainName.equals(that.domainName)
          : that.domainName != null) {
         return false;
      }

      return true;
   }

   @Override
   public int hashCode() {
      int result = domainID != null ? domainID.hashCode() : 0;
      result = 31 * result + (domainName != null ? domainName.hashCode() : 0);
      result = 31 * result + (parentDomainID != null ? parentDomainID.hashCode() : 0);
      return result;
   }

   @Override
   public String toString() {
      return "OACC_Domain{" +
            "domainID=" + domainID +
            ", domainName='" + domainName + '\'' +
            ", parentDomainID=" + parentDomainID +
            '}';
   }

   public static class Builder {
      private Long   domainID;
      private String domainName;
      private Long   parentDomainID;

      public Builder(Long domainID) {
         this.domainID = domainID;
      }

      public Builder domainName(String domainName) {
         this.domainName = domainName;
         return this;
      }

      public Builder parentDomainID(Long parentDomainID) {
         this.parentDomainID = parentDomainID;
         return this;
      }

      public OACC_Domain build() {
         return new OACC_Domain(this);
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

      public static OACC_Domain findByID(Connection con,
                                                String dbSchema,
                                                int domainID) throws SQLException {
         try (PreparedStatement preparedStatement
                    = con.prepareStatement("SELECT * FROM " + getQualifiedTableName(dbSchema) + " WHERE DomainID=?");
         ) {
            OACC_Domain resource = null;
            preparedStatement.setInt(1, domainID);
            ResultSet resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
               resource = getDB_Domain(resultSet);
            }
            if (resultSet.next()) {
               throw new IllegalStateException("found multiple rows in " + getQualifiedTableName(dbSchema) + " for the same primary key");
            }

            return resource;
         }
      }

      public static List<OACC_Domain> findByName(Connection con,
                                                        String dbSchema,
                                                        String domainName) throws SQLException {
         try (PreparedStatement preparedStatement
                    = con.prepareStatement("SELECT * FROM " + getQualifiedTableName(dbSchema) + " WHERE DomainName=?");
         ) {
            List<OACC_Domain> result = new ArrayList<>();
            preparedStatement.setString(1, domainName);
            ResultSet resultSet = preparedStatement.executeQuery();

            while (resultSet.next()) {
               result.add(getDB_Domain(resultSet));
            }

            return result;
         }
      }

      private static OACC_Domain getDB_Domain(ResultSet resultSet) throws SQLException {
         //return new Builder(resultSet.getObject("domainID", Integer.class))
         return new Builder(getLong(resultSet, "domainID"))
               .domainName(resultSet.getString("domainName"))
               //.parentDomainID(resultSet.getObject("parentDomainID", Integer.class))
               .parentDomainID(getLong(resultSet, "parentDomainID"))
               .build();
      }
   }
}
