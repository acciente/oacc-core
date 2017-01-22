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
import com.acciente.oacc.ResourceCreatePermission;
import com.acciente.oacc.ResourceCreatePermissions;
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public abstract class CommonGrantResourceCreatePermissionPostCreateSysPersister extends Persister implements GrantResourceCreatePermissionPostCreateSysPersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public CommonGrantResourceCreatePermissionPostCreateSysPersister(SQLProfile sqlProfile,
                                                                    SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public abstract Set<ResourceCreatePermission> getResourceCreatePostCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                                           Resource accessorResource,
                                                                                                           Id<ResourceClassId> resourceClassId,
                                                                                                           Id<DomainId> resourceDomainId);

   @Override
   public abstract Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreatePostCreateSysPermissionsIncludeInherited(
         SQLConnection connection,
         Resource accessorResource);

   @Override
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreatePostCreateSysPermissions(SQLConnection connection,
                                                                                                            Resource accessorResource) {
      SQLStatement statement = null;

      try {
         Map<String, Map<String, Set<ResourceCreatePermission>>> createSysPermissionsMap = new HashMap<>();
         SQLResult resultSet;

         // collect the system permissions that the accessor has and add it to createALLPermissionsMap
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourceCreatePermissionPostCreateSys_withoutInheritance_ResourceDomainName_ResourceClassName_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            final String resourceDomainName;
            final String resourceClassName;
            Map<String, Set<ResourceCreatePermission>> permissionsForResourceDomain;
            Set<ResourceCreatePermission> permissionsForResourceClass;

            resourceDomainName = resultSet.getString("DomainName");
            resourceClassName = resultSet.getString("ResourceClassName");

            if ((permissionsForResourceDomain = createSysPermissionsMap.get(resourceDomainName)) == null) {
               createSysPermissionsMap.put(resourceDomainName,
                                           permissionsForResourceDomain = new HashMap<>());
            }

            if ((permissionsForResourceClass = permissionsForResourceDomain.get(resourceClassName)) == null) {
               permissionsForResourceDomain.put(resourceClassName,
                                                permissionsForResourceClass = new HashSet<>());
            }

            permissionsForResourceClass.add(getResourceCreatePostCreateSysPermission(resultSet));
         }
         resultSet.close();

         return createSysPermissionsMap;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   protected static ResourceCreatePermission getResourceCreatePostCreateSysPermission(SQLResult resultSet) throws SQLException {
      ResourcePermission postCreatePermission;
      final String postCreateSysPermissionName = resultSet.getResourceSysPermissionName("PostCreateSysPermissionId");

      if (resultSet.getBoolean("PostCreateIsWithGrant")) {
         postCreatePermission = ResourcePermissions.getInstanceWithGrantOption(postCreateSysPermissionName);
      }
      else {
         postCreatePermission = ResourcePermissions.getInstance(postCreateSysPermissionName);
      }

      if (resultSet.getBoolean("IsWithGrant")) {
         return ResourceCreatePermissions.getInstanceWithGrantOption(postCreatePermission);
      }
      else {
         return ResourceCreatePermissions.getInstance(postCreatePermission);
      }
   }

   @Override
   public Set<ResourceCreatePermission> getResourceCreatePostCreateSysPermissions(SQLConnection connection,
                                                                                  Resource accessorResource,
                                                                                  Id<ResourceClassId> resourceClassId,
                                                                                  Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;
      try {
         SQLResult resultSet;
         Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();

         // collect the system permissions the accessor has to the specified resource class
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourceCreatePermissionPostCreateSys_withoutInheritance_PostCreateSysPermissionID_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourceCreatePermissions.add(getResourceCreatePostCreateSysPermission(resultSet));
         }
         resultSet.close();

         return resourceCreatePermissions;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void addResourceCreatePostCreateSysPermissions(SQLConnection connection,
                                                         Resource accessorResource,
                                                         Id<ResourceClassId> accessedResourceClassId,
                                                         Id<DomainId> accessedResourceDomainId,
                                                         Set<ResourceCreatePermission> requestedResourceCreatePermissions,
                                                         Resource grantorResource) {
      SQLStatement statement = null;
      try {
         // add the new post-create system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantResourceCreatePermissionPostCreateSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_PostCreateIsWithGrant_ResourceClassID_PostCreateSysPermissionID);
         for (ResourceCreatePermission resourceCreatePermission : requestedResourceCreatePermissions) {
            if (!resourceCreatePermission.isSystemPermission()
                  && resourceCreatePermission.getPostCreateResourcePermission().isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setResourceDomainId(3, accessedResourceDomainId);
               statement.setBoolean(4, resourceCreatePermission.isWithGrantOption());
               statement.setBoolean(5, resourceCreatePermission.getPostCreateResourcePermission().isWithGrantOption());
               statement.setResourceClassId(6, accessedResourceClassId);
               statement.setResourceSystemPermissionId(7, resourceCreatePermission.getPostCreateResourcePermission().getSystemPermissionId());

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
   public void updateResourceCreatePostCreateSysPermissions(SQLConnection connection,
                                                            Resource accessorResource,
                                                            Id<ResourceClassId> accessedResourceClassId,
                                                            Id<DomainId> accessedResourceDomainId,
                                                            Set<ResourceCreatePermission> requestedResourceCreatePermissions,
                                                            Resource grantorResource) {
      SQLStatement statement = null;
      try {
         // add the new post-create system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_updateInGrantResourceCreatePermissionPostCreateSys_SET_GrantorID_IsWithGrant_PostCreateIsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreateSysPermissionID);
         for (ResourceCreatePermission resourceCreatePermission : requestedResourceCreatePermissions) {
            if (!resourceCreatePermission.isSystemPermission()
                  && resourceCreatePermission.getPostCreateResourcePermission().isSystemPermission()) {
               statement.setResourceId(1, grantorResource);
               statement.setBoolean(2, resourceCreatePermission.isWithGrantOption());
               statement.setBoolean(3, resourceCreatePermission.getPostCreateResourcePermission().isWithGrantOption());
               statement.setResourceId(4, accessorResource);
               statement.setResourceDomainId(5, accessedResourceDomainId);
               statement.setResourceClassId(6, accessedResourceClassId);
               statement.setResourceSystemPermissionId(7, resourceCreatePermission.getPostCreateResourcePermission().getSystemPermissionId());

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
   public void removeAllResourceCreatePostCreateSysPermissions(SQLConnection connection,
                                                               Resource accessorResource) {
      SQLStatement statement = null;
      try {
         // revoke any existing post-create system permissions this accessor has to any domain + resource class
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID);
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
   public abstract void removeAllResourceCreatePostCreateSysPermissions(SQLConnection connection,
                                                                        Id<DomainId> accessedDomainId);

   @Override
   public void removeResourceCreatePostCreateSysPermissions(SQLConnection connection,
                                                            Resource accessorResource,
                                                            Id<ResourceClassId> accessedResourceClassId,
                                                            Id<DomainId> accessedResourceDomainId) {
      SQLStatement statement = null;
      try {
         // revoke any existing post-create system permissions this accessor has to this domain + resource class
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID_AccessedDomainID_ResourceClassID);
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
   public void removeResourceCreatePostCreateSysPermissions(SQLConnection connection,
                                                            Resource accessorResource,
                                                            Id<ResourceClassId> accessedResourceClassId,
                                                            Id<DomainId> accessedResourceDomainId,
                                                            Set<ResourceCreatePermission> requestedResourceCreatePermissions) {
      SQLStatement statement = null;
      try {
         // revoke the post-create system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourceCreatePermissionPostCreateSys_BY_AccessorID_AccessedDomainID_ResourceClassID_PostCreateSysPermissionID);
         for (ResourceCreatePermission resourceCreatePermission : requestedResourceCreatePermissions) {
            if (!resourceCreatePermission.isSystemPermission()
                  && resourceCreatePermission.getPostCreateResourcePermission().isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceDomainId(2, accessedResourceDomainId);
               statement.setResourceClassId(3, accessedResourceClassId);
               statement.setResourceSystemPermissionId(4, resourceCreatePermission.getPostCreateResourcePermission().getSystemPermissionId());

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
