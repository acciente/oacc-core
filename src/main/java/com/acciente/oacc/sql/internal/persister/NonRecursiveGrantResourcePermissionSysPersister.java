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
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

public class NonRecursiveGrantResourcePermissionSysPersister extends CommonGrantResourcePermissionSysPersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public NonRecursiveGrantResourcePermissionSysPersister(SQLProfile sqlProfile,
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
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // now accumulate the objects of the specified type that each (inherited) accessor has the specified permission to
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_ResourceClassID_SysPermissionID_IsWithGrant);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            statement.setResourceId(1, accessorResourceId);
            statement.setResourceClassId(2, resourceClassId);
            statement.setResourceSystemPermissionId(3, resourcePermission.getSystemPermissionId());
            statement.setBoolean(4, resourcePermission.isWithGrantOption());
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               resources.add(resultSet.getResource("ResourceId", "ExternalId"));
            }
            resultSet.close();
         }

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
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // then get all the descendants of the specified domain
         final Set<Id<DomainId>> descendantDomainIds
               = NonRecursivePersisterHelper.getDescendantDomainIdsOrderedByAscendingLevel(sqlStrings,
                                                                                           connection,
                                                                                           resourceDomainId);

         // now accumulate the objects of the specified type that each (inherited) accessor
         // has the specified permission to in each of the descendant domains
         SQLResult resultSet;
         Set<Resource> resources = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceID_ExternalID_BY_AccessorID_DomainID_ResourceClassID_SysPermissionID_IsWithGrant);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            for (Id<DomainId> descendantDomainId : descendantDomainIds) {
               statement.setResourceId(1, accessorResourceId);
               statement.setResourceDomainId(2, descendantDomainId);
               statement.setResourceClassId(3, resourceClassId);
               statement.setResourceSystemPermissionId(4, resourcePermission.getSystemPermissionId());
               statement.setBoolean(5, resourcePermission.isWithGrantOption());
               resultSet = statement.executeQuery();

               while (resultSet.next()) {
                  resources.add(resultSet.getResource("ResourceId", "ExternalId"));
               }
               resultSet.close();
            }
         }

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
         // first get all the resources from which the accessor inherits any permissions
         final Set<Id<ResourceId>> accessorResourceIds
               = NonRecursivePersisterHelper.getInheritedAccessorResourceIds(sqlStrings, connection, accessorResource);

         // now accumulate the objects of the specified type that each (inherited) accessor has the specified permission to
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourcePermissionSys_withoutInheritance_ResourceClassName_SysPermissionID_IsWithGrant_BY_AccessorID_AccessedID);

         for (Id<ResourceId> accessorResourceId : accessorResourceIds) {
            statement.setResourceId(1, accessorResourceId);
            statement.setResourceId(2, accessedResource);
            resultSet = statement.executeQuery();

            while (resultSet.next()) {
               resourcePermissions.add(getResourceSysPermission(resultSet));
            }
            resultSet.close();
         }

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
