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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OACC_Grant_DomPerm_Sys extends DbBase {
   private final Long  accessorResourceID;
   private final Long  accessedDomainID;
   private final Long  sysPermissionID;
   private final Short isWithGrant;
   private final Long  grantorResourceID;

   private static String getQualifiedTableName(String schemaName) {
      return getSchemaAndTableNamePrefix(schemaName) + "Grant_DomPerm_Sys";
   }

   private static String getPKColumnNames() {
      return "AccessorResourceID, AccessedDomainID, SysPermissionID";
   }

   OACC_Grant_DomPerm_Sys(Builder builder) {
      this.accessorResourceID = builder.accessorResourceID;
      this.accessedDomainID = builder.accessedDomainID;
      this.sysPermissionID = builder.sysPermissionID;
      this.isWithGrant = builder.isWithGrant;
      this.grantorResourceID = builder.grantorResourceID;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      }
      if (o == null || getClass() != o.getClass()) {
         return false;
      }

      OACC_Grant_DomPerm_Sys that = (OACC_Grant_DomPerm_Sys) o;

      if (accessedDomainID != null
          ? !accessedDomainID.equals(that.accessedDomainID)
          : that.accessedDomainID != null) {
         return false;
      }
      if (accessorResourceID != null
          ? !accessorResourceID.equals(that.accessorResourceID)
          : that.accessorResourceID != null) {
         return false;
      }
      if (grantorResourceID != null
          ? !grantorResourceID.equals(that.grantorResourceID)
          : that.grantorResourceID != null) {
         return false;
      }
      if (isWithGrant != null ? !isWithGrant.equals(that.isWithGrant) : that.isWithGrant != null) {
         return false;
      }
      if (sysPermissionID != null ? !sysPermissionID.equals(that.sysPermissionID) : that.sysPermissionID != null) {
         return false;
      }

      return true;
   }

   @Override
   public int hashCode() {
      int result = accessorResourceID != null ? accessorResourceID.hashCode() : 0;
      result = 31 * result + (accessedDomainID != null ? accessedDomainID.hashCode() : 0);
      result = 31 * result + (sysPermissionID != null ? sysPermissionID.hashCode() : 0);
      result = 31 * result + (isWithGrant != null ? isWithGrant.hashCode() : 0);
      result = 31 * result + (grantorResourceID != null ? grantorResourceID.hashCode() : 0);
      return result;
   }

   @Override
   public String toString() {
      return "OACC_Grant_DomPerm_Sys{" +
            "accessorResourceID=" + accessorResourceID +
            ", accessedDomainID=" + accessedDomainID +
            ", sysPermissionID=" + sysPermissionID +
            ", isWithGrant=" + isWithGrant +
            ", grantorResourceID=" + grantorResourceID +
            '}';
   }

   public static class Builder {
      private Long  accessorResourceID;
      private Long  accessedDomainID;
      private Long  sysPermissionID;
      private Short isWithGrant;
      private Long  grantorResourceID;

      public Builder(Long accessorResourceID, Long accessedDomainID, Long sysPermissionID) {
         this.accessorResourceID = accessorResourceID;
         this.accessedDomainID = accessedDomainID;
         this.sysPermissionID = sysPermissionID;
      }

      public Builder isWithGrant(Boolean isWithGrant) {
         this.isWithGrant = isWithGrant == null ? null : (short) (isWithGrant ? 1 : 0);
         return this;
      }

      public Builder grantorResourceID(Long grantorResourceID) {
         this.grantorResourceID = grantorResourceID;
         return this;
      }

      public OACC_Grant_DomPerm_Sys build() {
         return new OACC_Grant_DomPerm_Sys(this);
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

      public static List<OACC_Grant_DomPerm_Sys> findByAccessorIDAndAccessedID(Connection con,
                                                                                 String dbSchema,
                                                                                 Long accessorResourceID,
                                                                                 Long accessedDomainID) throws SQLException {
         try (PreparedStatement preparedStatement
                    = con.prepareStatement("SELECT * FROM " + getQualifiedTableName(dbSchema) + " WHERE AccessorResourceID=? AND AccessedDomainID=?");
         ) {
            List<OACC_Grant_DomPerm_Sys> result = new ArrayList<>();
            preparedStatement.setLong(1, accessorResourceID);
            preparedStatement.setLong(2, accessedDomainID);
            ResultSet resultSet = preparedStatement.executeQuery();

            while (resultSet.next()) {
               result.add(getDB_Granted_Domain_SysPermission(resultSet));
            }

            return result;
         }
      }

      private static OACC_Grant_DomPerm_Sys getDB_Granted_Domain_SysPermission(ResultSet resultSet) throws SQLException {
         final Short isWithGrant = getShort(resultSet, "isWithGrant");
         return new Builder(getLong(resultSet, "accessorResourceID"),
                            getLong(resultSet, "accessedDomainID"),
                            getLong(resultSet, "sysPermissionID"))
               .isWithGrant(isWithGrant == null ? null : isWithGrant == 0 ? false : true)
               .grantorResourceID(getLong(resultSet, "grantorResourceID"))
               .build();
      }
   }
}
