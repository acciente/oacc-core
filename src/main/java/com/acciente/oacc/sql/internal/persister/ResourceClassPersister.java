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

import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.ResourceClassInternalInfo;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.LinkedList;
import java.util.List;

public class ResourceClassPersister extends Persister implements Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   private final   SQLStrings sqlStrings;

   public ResourceClassPersister(SQLProfile sqlProfile,
                                 SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   public Id<ResourceClassId> getResourceClassId(SQLConnection connection,
                                                 String resourceClassName) {
      SQLStatement statement = null;

      try {
         Id<ResourceClassId> resourceClassId = null;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResourceClass_ResourceClassID_BY_ResourceClassName);
         statement.setString(1, resourceClassName);
         SQLResult resultSet = statement.executeQuery();

         if (resultSet.next()) {
            resourceClassId = resultSet.getResourceClassId("ResourceClassId");
         }

         return resourceClassId;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public ResourceClassInternalInfo getResourceClassInfo(SQLConnection connection,
                                                         String resourceClassName) {
      SQLStatement statement = null;

      if (resourceClassName == null) {
         throw new IllegalArgumentException("Resource class name cannot be null");
      }

      try {
         ResourceClassInternalInfo resourceClassInternalInfo = null;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResourceClass_ResourceClassID_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed_BY_ResourceClassName);
         statement.setString(1, resourceClassName.trim());
         SQLResult resultSet = statement.executeQuery();

         if (resultSet.next()) {
            resourceClassInternalInfo = new ResourceClassInternalInfo(resultSet.getResourceClassId("ResourceClassId"),
                                                                      resultSet.getString("ResourceClassName"),
                                                                      resultSet.getBoolean("IsAuthenticatable"),
                                                                      resultSet.getBoolean("IsUnauthenticatedCreateAllowed"));
         }

         return resourceClassInternalInfo;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public ResourceClassInternalInfo getResourceClassInfoByResourceId(SQLConnection connection,
                                                                     Resource resource) {
      SQLStatement statement = null;

      try {
         ResourceClassInternalInfo resourceClassInternalInfo = null;

         statement = connection.prepareStatement(sqlStrings.SQL_findInResourceClass_ResourceClassID_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed_BY_ResourceID);
         statement.setResourceId(1, resource);
         SQLResult resultSet = statement.executeQuery();

         if (resultSet.next()) {
            resourceClassInternalInfo = new ResourceClassInternalInfo(resultSet.getResourceClassId("ResourceClassId"),
                                                                      resultSet.getString("ResourceClassName"),
                                                                      resultSet.getBoolean("IsAuthenticatable"),
                                                                      resultSet.getBoolean("IsUnauthenticatedCreateAllowed"));
         }

         if (resourceClassInternalInfo == null) {
            throw new IllegalArgumentException("Could not determine resource class for resource: " + resource);
         }

         return resourceClassInternalInfo;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   public List<String> getResourceClassNames(SQLConnection connection) {
      SQLStatement statement = null;

      try {
         List<String> resourceClassNames = new LinkedList<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInResourceClass_ResourceClassName_BY_ALL);
         SQLResult resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourceClassNames.add(resultSet.getString("ResourceClassName"));
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

   public void addResourceClass(SQLConnection connection,
                                String resourceClassName,
                                boolean authenticatable,
                                boolean nonAuthenticatedCreateAllowed) {
      SQLStatement statement = null;

      try {
         // create the new resource class
         statement = connection.prepareStatement(sqlStrings.SQL_createInResourceClass_WITH_ResourceClassName_IsAuthenticatable_IsUnauthenticatedCreateAllowed);
         statement.setString(1, resourceClassName);
         statement.setBoolean(2, authenticatable);
         statement.setBoolean(3, nonAuthenticatedCreateAllowed);
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
