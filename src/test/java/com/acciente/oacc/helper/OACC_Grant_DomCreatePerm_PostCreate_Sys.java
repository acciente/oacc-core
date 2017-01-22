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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OACC_Grant_DomCreatePerm_PostCreate_Sys extends DbBase {
   private final Long  accessorResourceID;
   private final Long  postCreateSysPermissionID;
   private final Short postCreateIsWithGrant;
   private final Short isWithGrant;
   private final Long  grantorResourceID;

   private static String getQualifiedTableName(String schemaName) {
      return getSchemaAndTableNamePrefix(schemaName) + "Grant_DomCrPerm_PostCr_Sys";
   }

   private static String getPKColumnNames() {
      return "AccessorResourceID, PostCreateSysPermissionId";
   }

   OACC_Grant_DomCreatePerm_PostCreate_Sys(Builder builder) {
      accessorResourceID = builder.accessorResourceID;
      postCreateSysPermissionID = builder.postCreateSysPermissionID;
      postCreateIsWithGrant = builder.postCreateIsWithGrant;
      isWithGrant = builder.isWithGrant;
      grantorResourceID = builder.grantorResourceID;
   }

   public Long getAccessorResourceID() {
      return accessorResourceID;
   }

   public Long getPostCreateSysPermissionID() {
      return postCreateSysPermissionID;
   }

   public Short getPostCreateIsWithGrant() {
      return postCreateIsWithGrant;
   }

   public Short getWithGrant() {
      return isWithGrant;
   }

   public Long getGrantorResourceID() {
      return grantorResourceID;
   }

   @Override
   public boolean equals(Object o) {
      if (this == o) {
         return true;
      }
      if (o == null || getClass() != o.getClass()) {
         return false;
      }

      OACC_Grant_DomCreatePerm_PostCreate_Sys that = (OACC_Grant_DomCreatePerm_PostCreate_Sys) o;

      if (accessorResourceID != null
          ? !accessorResourceID.equals(that.accessorResourceID)
          : that.accessorResourceID != null) {
         return false;
      }
      if (postCreateIsWithGrant != null
          ? !postCreateIsWithGrant.equals(that.postCreateIsWithGrant)
          : that.postCreateIsWithGrant != null) {
         return false;
      }
      if (postCreateSysPermissionID != null
          ? !postCreateSysPermissionID.equals(that.postCreateSysPermissionID)
          : that.postCreateSysPermissionID != null) {
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

      return true;
   }

   @Override
   public int hashCode() {
      int result = accessorResourceID != null ? accessorResourceID.hashCode() : 0;
      result = 31 * result + (postCreateSysPermissionID != null ? postCreateSysPermissionID.hashCode() : 0);
      result = 31 * result + (postCreateIsWithGrant != null ? postCreateIsWithGrant.hashCode() : 0);
      result = 31 * result + (isWithGrant != null ? isWithGrant.hashCode() : 0);
      result = 31 * result + (grantorResourceID != null ? grantorResourceID.hashCode() : 0);
      return result;
   }

   @Override
   public String toString() {
      return "OACC_Grant_DomCreatePerm_PostCreate_Sys{" +
            "accessorResourceID=" + accessorResourceID +
            ", postCreateSysPermissionID=" + postCreateSysPermissionID +
            ", postCreateIsWithGrant=" + postCreateIsWithGrant +
            ", isWithGrant=" + isWithGrant +
            ", grantorResourceID=" + grantorResourceID +
            '}';
   }

   public static class Builder {
      private Long  accessorResourceID;
      private Long  postCreateSysPermissionID;
      private Short postCreateIsWithGrant;
      private Short isWithGrant;
      private Long  grantorResourceID;

      public Builder(Long accessorResourceID, Long postCreateSysPermissionID) {
         this.accessorResourceID = accessorResourceID;
         this.postCreateSysPermissionID = postCreateSysPermissionID;
      }

      public Builder postCreateIsWithGrant(Boolean postCreateIsWithGrant) {
         this.postCreateIsWithGrant = postCreateIsWithGrant == null ? null : (short) (postCreateIsWithGrant ? 1 : 0);
         return this;
      }

      public Builder isWithGrant(Boolean withGrant) {
         isWithGrant = withGrant == null ? null : (short) (withGrant ? 1 : 0);
         return this;
      }

      public Builder grantorResourceID(Long grantorResourceID) {
         this.grantorResourceID = grantorResourceID;
         return this;
      }

      public OACC_Grant_DomCreatePerm_PostCreate_Sys build() {
         return new OACC_Grant_DomCreatePerm_PostCreate_Sys(this);
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

      public static List<OACC_Grant_DomCreatePerm_PostCreate_Sys> findByAccessorID(Connection con,
                                                                       String dbSchema,
                                                                       Long accessorResourceID) throws SQLException {
         try (PreparedStatement preparedStatement
                    = con.prepareStatement("SELECT * FROM " + getQualifiedTableName(dbSchema) + " WHERE AccessorResourceID=?");
         ) {
            List<OACC_Grant_DomCreatePerm_PostCreate_Sys> result = new ArrayList<>();
            preparedStatement.setLong(1, accessorResourceID);
            ResultSet resultSet = preparedStatement.executeQuery();

            while (resultSet.next()) {
               result.add(getDB_Granted_CreateDomain_SysPermission(resultSet));
            }

            return result;
         }
      }

      private static OACC_Grant_DomCreatePerm_PostCreate_Sys getDB_Granted_CreateDomain_SysPermission(
            ResultSet resultSet) throws SQLException {
         final Short postCreateIsWithGrant = getShort(resultSet, "postCreateIsWithGrant");
         final Short isWithGrant = getShort(resultSet, "isWithGrant");
         return new Builder(getLong(resultSet, "accessorResourceID"),
                            getLong(resultSet, "postCreateSysPermissionID"))
               .postCreateIsWithGrant(postCreateIsWithGrant == null ? null : postCreateIsWithGrant == 0 ? false : true)
               .isWithGrant(isWithGrant == null ? null : isWithGrant == 0 ? false : true)
               .grantorResourceID(getLong(resultSet, "grantorResourceID"))
               .build();
      }
   }
}
