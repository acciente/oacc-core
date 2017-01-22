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
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourcePermissionId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class CommonGrantGlobalResourcePermissionPersister extends Persister implements GrantGlobalResourcePermissionPersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public CommonGrantGlobalResourcePermissionPersister(SQLProfile sqlProfile,
                                                       SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public abstract Set<Resource> getResourcesByGlobalResourcePermission(SQLConnection connection,
                                                                        Resource accessorResource,
                                                                        Id<ResourceClassId> resourceClassId,
                                                                        ResourcePermission resourcePermission,
                                                                        Id<ResourcePermissionId> resourcePermissionId);

   @Override
   public abstract Set<Resource> getResourcesByGlobalResourcePermission(SQLConnection connection,
                                                                        Resource accessorResource,
                                                                        Id<ResourceClassId> resourceClassId,
                                                                        Id<DomainId> resourceDomainId,
                                                                        ResourcePermission resourcePermission,
                                                                        Id<ResourcePermissionId> resourcePermissionId);

   @Override
   public abstract Set<ResourcePermission> getGlobalResourcePermissionsIncludeInherited(SQLConnection connection,
                                                                                        Resource accessorResource,
                                                                                        Id<ResourceClassId> resourceClassId,
                                                                                        Id<DomainId> resourceDomainId);

   @Override
   public Set<ResourcePermission> getGlobalResourcePermissions(SQLConnection connection,
                                                               Resource accessorResource,
                                                               Id<ResourceClassId> resourceClassId,
                                                               Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;
      try {
         // collect the system permissions that the accessor has to the accessed resource directly
         SQLResult resultSet;
         Set<ResourcePermission> resourcePermissions = new HashSet<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermission_withoutInheritance_PermissionName_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourcePermissions.add(getResourcePermission(resultSet));
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

   protected static ResourcePermission getResourcePermission(SQLResult resultSet) throws SQLException {
      final String permissionName = resultSet.getString("PermissionName");

      if (resultSet.getBoolean("IsWithGrant")) {
         return ResourcePermissions.getInstanceWithGrantOption(permissionName);
      }
      else {
         return ResourcePermissions.getInstance(permissionName);
      }
   }

   @Override
   public abstract Map<String, Map<String, Set<ResourcePermission>>> getGlobalResourcePermissionsIncludeInherited(SQLConnection connection,
                                                                                                                  Resource accessorResource);

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalResourcePermissions(SQLConnection connection,
                                                                                         Resource accessorResource) {
      SQLStatement statement = null;
      try {
         // collect the non-system permissions that the accessor has
         SQLResult resultSet;
         final Map<String, Map<String, Set<ResourcePermission>>> globalPermissionsMap = new HashMap<>();

         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantGlobalResourcePermission_withoutInheritance_ResourceDomainName_ResourceClassName_PermissionName_IsWithGrant_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            final String resourceDomainName;
            final String resourceClassName;
            Map<String, Set<ResourcePermission>> permissionsForResourceDomain;
            Set<ResourcePermission> resourcePermissionsForResourceClass;

            resourceDomainName = resultSet.getString("DomainName");
            resourceClassName = resultSet.getString("ResourceClassName");

            if ((permissionsForResourceDomain = globalPermissionsMap.get(resourceDomainName)) == null) {
               globalPermissionsMap.put(resourceDomainName,
                                        permissionsForResourceDomain = new HashMap<>());
            }

            if ((resourcePermissionsForResourceClass = permissionsForResourceDomain.get(resourceClassName)) == null) {
               permissionsForResourceDomain.put(resourceClassName,
                                                resourcePermissionsForResourceClass = new HashSet<>());
            }

            resourcePermissionsForResourceClass.add(getResourcePermission(resultSet));
         }
         resultSet.close();

         return globalPermissionsMap;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void addGlobalResourcePermissions(SQLConnection connection,
                                            Resource accessorResource,
                                            Id<ResourceClassId> accessedResourceClassId,
                                            Id<DomainId> accessedResourceDomainId,
                                            Set<ResourcePermission> requestedResourcePermissions,
                                            Resource grantorResource) {
      SQLStatement statement = null;
      try {
         // add the new non-system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantGlobalResourcePermission_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_PermissionName);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (!resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setResourceDomainId(3, accessedResourceDomainId);
               statement.setBoolean(4, resourcePermission.isWithGrantOption());
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setString(6, resourcePermission.getPermissionName());

               assertOneRowInserted(statement.executeUpdate());
            }
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void updateGlobalResourcePermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               Id<ResourceClassId> accessedResourceClassId,
                                               Id<DomainId> accessedResourceDomainId,
                                               Set<ResourcePermission> requestedResourcePermissions,
                                               Resource grantorResource) {
      SQLStatement statement = null;
      try {
         // add the new non-system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_updateInGrantGlobalResourcePermission_SET_GrantorID_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_PermissionName);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (!resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, grantorResource);
               statement.setBoolean(2, resourcePermission.isWithGrantOption());
               statement.setResourceId(3, accessorResource);
               statement.setResourceDomainId(4, accessedResourceDomainId);
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setString(6, resourcePermission.getPermissionName());

               assertOneRowUpdated(statement.executeUpdate());
            }
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void removeAllGlobalResourcePermissions(SQLConnection connection,
                                                  Resource accessorResource) {

      SQLStatement statement = null;
      try {
         // revoke any existing non-system permissions this accessor has to any domain + resource class
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantGlobalResourcePermission_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         statement.executeUpdate();
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public abstract void removeAllGlobalResourcePermissions(SQLConnection connection,
                                                           Id<DomainId> accessedDomainId);

   @Override
   public void removeGlobalResourcePermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               Id<ResourceClassId> accessedResourceClassId,
                                               Id<DomainId> accessedResourceDomainId) {

      SQLStatement statement = null;
      try {
         // revoke any existing non-system permissions this accessor has to this domain + resource class
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, accessedResourceDomainId);
         statement.setResourceClassId(3, accessedResourceClassId);
         statement.executeUpdate();
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void removeGlobalResourcePermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               Id<ResourceClassId> accessedResourceClassId,
                                               Id<DomainId> accessedResourceDomainId,
                                               Set<ResourcePermission> requestedResourcePermissions) {
      SQLStatement statement = null;
      try {
         // remove the specified non-system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantGlobalResourcePermission_BY_AccessorID_AccessedDomainID_ResourceClassID_PermissionName);
         for (ResourcePermission resourcePermission : requestedResourcePermissions) {
            if (!resourcePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceDomainId(2, accessedResourceDomainId);
               statement.setResourceClassId(3, accessedResourceClassId);
               statement.setString(4, resourcePermission.getPermissionName());

               assertOneRowUpdated(statement.executeUpdate());
            }
         }
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }
}
