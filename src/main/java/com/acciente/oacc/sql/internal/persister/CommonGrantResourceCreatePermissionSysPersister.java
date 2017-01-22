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

public abstract class CommonGrantResourceCreatePermissionSysPersister extends Persister implements GrantResourceCreatePermissionSysPersister, Serializable {
   private static final long serialVersionUID = 1L;

   protected final SQLProfile sqlProfile;
   protected final SQLStrings sqlStrings;

   public CommonGrantResourceCreatePermissionSysPersister(SQLProfile sqlProfile,
                                                          SQLStrings sqlStrings) {
      this.sqlProfile = sqlProfile;
      this.sqlStrings = sqlStrings;
   }

   @Override
   public abstract Set<ResourceCreatePermission> getResourceCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                                 Resource accessorResource,
                                                                                                 Id<ResourceClassId> resourceClassId,
                                                                                                 Id<DomainId> resourceDomainId);

   @Override
   public abstract Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                                                           Resource accessorResource);

   @Override
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreateSysPermissions(SQLConnection connection,
                                                                                                  Resource accessorResource) {
      SQLStatement statement = null;

      try {
         Map<String, Map<String, Set<ResourceCreatePermission>>> createSysPermissionsMap = new HashMap<>();
         SQLResult resultSet;

         // collect the system permissions that the accessor has and add it to createALLPermissionsMap
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourceCreatePermissionSys_withoutInheritance_ResourceDomainName_ResourceClassName_SysPermissionId_IsWithGrant_BY_AccessorID);
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

            permissionsForResourceClass.add(getResourceCreateSysPermission(resultSet));
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

   protected static ResourceCreatePermission getResourceCreateSysPermission(SQLResult resultSet) throws SQLException {
      final String sysPermissionName = resultSet.getResourceCreateSysPermissionName("SysPermissionId");

      if (resultSet.getBoolean("IsWithGrant")) {
         return ResourceCreatePermissions.getInstanceWithGrantOption(sysPermissionName);
      }
      else {
         return ResourceCreatePermissions.getInstance(sysPermissionName);
      }
   }

   @Override
   public Set<ResourceCreatePermission> getResourceCreateSysPermissions(SQLConnection connection,
                                                                        Resource accessorResource,
                                                                        Id<ResourceClassId> resourceClassId,
                                                                        Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;
      try {
         SQLResult resultSet;
         Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();

         // collect the system permissions the accessor has to the specified resource class
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourceCreatePermissionSys_withoutInheritance_SysPermissionId_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourceCreatePermissions.add(getResourceCreateSysPermission(resultSet));
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
   public void addResourceCreateSysPermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               Id<ResourceClassId> accessedResourceClassId,
                                               Id<DomainId> accessedResourceDomainId,
                                               Set<ResourceCreatePermission> requestedResourceCreatePermissions,
                                               Resource grantorResource) {
      SQLStatement statement = null;
      try {
         // add the new create system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_createInGrantResourceCreatePermissionSys_WITH_AccessorID_GrantorID_AccessedDomainID_IsWithGrant_ResourceClassID_SysPermissionId);
         for (ResourceCreatePermission resourceCreatePermission : requestedResourceCreatePermissions) {
            if (resourceCreatePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceId(2, grantorResource);
               statement.setResourceDomainId(3, accessedResourceDomainId);
               statement.setBoolean(4, resourceCreatePermission.isWithGrantOption());
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setResourceCreateSystemPermissionId(6, resourceCreatePermission.getSystemPermissionId());

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
   public void updateResourceCreateSysPermissions(SQLConnection connection,
                                                  Resource accessorResource,
                                                  Id<ResourceClassId> accessedResourceClassId,
                                                  Id<DomainId> accessedResourceDomainId,
                                                  Set<ResourceCreatePermission> requestedResourceCreatePermissions,
                                                  Resource grantorResource) {
      SQLStatement statement = null;
      try {
         // add the new create system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_updateInGrantResourceCreatePermissionSys_SET_GrantorID_IsWithGrant_BY__AccessorID_AccessedDomainID_ResourceClassID_SysPermissionId);
         for (ResourceCreatePermission resourceCreatePermission : requestedResourceCreatePermissions) {
            if (resourceCreatePermission.isSystemPermission()) {
               statement.setResourceId(1, grantorResource);
               statement.setBoolean(2, resourceCreatePermission.isWithGrantOption());
               statement.setResourceId(3, accessorResource);
               statement.setResourceDomainId(4, accessedResourceDomainId);
               statement.setResourceClassId(5, accessedResourceClassId);
               statement.setResourceCreateSystemPermissionId(6, resourceCreatePermission.getSystemPermissionId());

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
   public void removeAllResourceCreateSysPermissions(SQLConnection connection,
                                                     Resource accessorResource) {
      SQLStatement statement = null;
      try {
         // revoke any existing create system permissions this accessor has to any domain + resource class
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID);
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
   public abstract void removeAllResourceCreateSysPermissions(SQLConnection connection,
                                                              Id<DomainId> accessedDomainId);

   @Override
   public void removeResourceCreateSysPermissions(SQLConnection connection,
                                                  Resource accessorResource,
                                                  Id<ResourceClassId> accessedResourceClassId,
                                                  Id<DomainId> accessedResourceDomainId) {
      SQLStatement statement = null;
      try {
         // revoke any existing create system permissions this accessor has to this domain + resource class
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID);
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
   public void removeResourceCreateSysPermissions(SQLConnection connection,
                                                  Resource accessorResource,
                                                  Id<ResourceClassId> accessedResourceClassId,
                                                  Id<DomainId> accessedResourceDomainId,
                                                  Set<ResourceCreatePermission> requestedResourceCreatePermissions) {
      SQLStatement statement = null;
      try {
         // revoke the create system permissions
         statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourceCreatePermissionSys_BY_AccessorID_AccessedDomainID_ResourceClassID_SysPermissionID);
         for (ResourceCreatePermission resourceCreatePermission : requestedResourceCreatePermissions) {
            if (resourceCreatePermission.isSystemPermission()) {
               statement.setResourceId(1, accessorResource);
               statement.setResourceDomainId(2, accessedResourceDomainId);
               statement.setResourceClassId(3, accessedResourceClassId);
               statement.setResourceCreateSystemPermissionId(4, resourceCreatePermission.getSystemPermissionId());

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
