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
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class RecursiveGrantResourcePermissionSysPersister extends CommonGrantResourcePermissionSysPersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public RecursiveGrantResourcePermissionSysPersister(SQLProfile sqlProfile,
                                                       SQLStrings sqlStrings) {
      super(sqlProfile, sqlStrings);
   }

   @Override
   public Set<Resource> getResourcesByResourceSysPermission(SQLConnection connection,
                                                            Resource accessorResource,
                                                            Id<ResourceClassId> resourceClassId,
                                                            ResourcePermission resourcePermission) {
      if (!resourcePermission.isSystemPermission()) {
         throw new IllegalArgumentException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via direct permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant);
         statement.setResourceId(1, accessorResource);
         statement.setResourceClassId(2, resourceClassId);
         statement.setResourceSystemPermissionId(3, resourcePermission.getSystemPermissionId());
         statement.setBoolean(4, resourcePermission.isWithGrantOption());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId", "ExternalId"));
         }
         resultSet.close();

         return resources;

      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public Set<Resource> getResourcesByResourceSysPermission(SQLConnection connection,
                                                            Resource accessorResource,
                                                            Id<ResourceClassId> resourceClassId,
                                                            Id<DomainId> resourceDomainId,
                                                            ResourcePermission resourcePermission) {
      if (!resourcePermission.isSystemPermission()) {
         throw new IllegalArgumentException("Permission: " + resourcePermission + " is not a system permission");
      }

      SQLStatement statement = null;
      try {
         // get the list of objects of the specified type that the session has access to via direct permissions
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         statement.setResourceSystemPermissionId(4, resourcePermission.getSystemPermissionId());
         statement.setBoolean(5, resourcePermission.isWithGrantOption());
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resources.add(resultSet.getResource("ResourceId", "ExternalId"));
         }
         resultSet.close();

         return resources;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public Set<ResourcePermission> getResourceSysPermissionsIncludeInherited(SQLConnection connection,
                                                                            Resource accessorResource,
                                                                            Resource accessedResource) {
      SQLStatement statement = null;
      try {
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         // collect the system permissions that the accessor this resource has to the accessor resource
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceId(2, accessedResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(getResourceSysPermission(resultSet));
         }
         resultSet.close();

         return resourcePermissions;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }
}
