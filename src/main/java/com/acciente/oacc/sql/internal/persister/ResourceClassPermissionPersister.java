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
package com.acciente.oacc.sql.internal.persister;

import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourcePermissionId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;

public class ResourceClassPermissionPersister extends Persister implements Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   private final   SQLStrings sqlStrings;

   public ResourceClassPermissionPersister(SQLProfile sqlProfile,
                                           SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   public Id<ResourcePermissionId> getResourceClassPermissionId(SQLConnection connection,
                                                                Id<ResourceClassId> resourceClassId,
                                                                String permissionName) {
      SQLStatement statement = null;
      try {
         Id<ResourcePermissionId> permissionId = null;

         // check if the permission name is already defined!
         statement = connection.prepareStatement(sqlStrings.SQL_findInResourceClassPermission_PermissionID_BY_ResourceClassID_PermissionName);
         statement.setResourceClassId(1, resourceClassId);
         statement.setString(2, permissionName);
         SQLResult resultSet = statement.executeQuery();

         if (resultSet.next()) {
            permissionId = resultSet.getResourcePermissionId("PermissionId");
         }
         resultSet.close();

         return permissionId;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public List<String> getPermissionNames(SQLConnection connection, String resourceClassName) {
      SQLStatement statement = null;

      try {
         List<String> resourceClassNames = new LinkedList<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInResourceClassPermission_PermissionName_BY_ResourceClassName);
         statement.setString(1, resourceClassName);
         SQLResult resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourceClassNames.add(resultSet.getString("PermissionName"));
         }

         return resourceClassNames;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public void addResourceClassPermission(SQLConnection connection,
                                          Id<ResourceClassId> resourceClassId,
                                          String permissionName) {
      SQLStatement statement = null;

      try {
         // finally add the new permission
         statement = connection.prepareStatement(sqlStrings.SQL_createInResourceClassPermission_WITH_ResourceClassID_PermissionName);
         statement.setResourceClassId(1, resourceClassId);
         statement.setString(2, permissionName);
         assertOneRowInserted(statement.executeUpdate());
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }
}
