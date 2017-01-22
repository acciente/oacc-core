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
import com.acciente.oacc.sql.SQLProfile;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.io.Serializable;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class RecursiveGrantResourceCreatePermissionPostCreatePersister extends CommonGrantResourceCreatePermissionPostCreatePersister implements Serializable {
   private static final long serialVersionUID = 1L;

   public RecursiveGrantResourceCreatePermissionPostCreatePersister(SQLProfile sqlProfile,
                                                                    SQLStrings sqlStrings) {
      super(sqlProfile, sqlStrings);
   }

   @Override
   public Set<ResourceCreatePermission> getResourceCreatePostCreatePermissionsIncludeInherited(SQLConnection connection,
                                                                                               Resource accessorResource,
                                                                                               Id<ResourceClassId> resourceClassId,
                                                                                               Id<DomainId> resourceDomainId) {
      SQLStatement statement = null;

      try {
         SQLResult resultSet;
         Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();

         // collect the non-system permissions the accessor has to the specified resource class
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourceCreatePermissionPostCreate_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID_AccessedDomainID_ResourceClassID);
         statement.setResourceId(1, accessorResource);
         statement.setResourceDomainId(2, resourceDomainId);
         statement.setResourceClassId(3, resourceClassId);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            resourceCreatePermissions.add(getResourceCreatePostCreatePermission(resultSet));
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
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreatePostCreatePermissionsIncludeInherited(
         SQLConnection connection,
         Resource accessorResource) {
      SQLStatement statement = null;

      try {
         Map<String, Map<String, Set<ResourceCreatePermission>>> createPermissionsMap = new HashMap<>();
         SQLResult resultSet;

         // collect the non-system permissions that the accessor has and add it to createALLPermissionsMap
         statement = connection.prepareStatement(sqlStrings.SQL_findInGrantResourceCreatePermissionPostCreate_ResourceDomainName_ResourceClassName_PostCreatePermissionName_PostCreateIsWithGrant_IsWithGrant_BY_AccessorID);
         statement.setResourceId(1, accessorResource);
         resultSet = statement.executeQuery();

         while (resultSet.next()) {
            final String resourceDomainName;
            final String resourceClassName;
            Map<String, Set<ResourceCreatePermission>> permissionsForResourceDomain;
            Set<ResourceCreatePermission> permissionsForResourceClass;

            resourceDomainName = resultSet.getString("DomainName");
            resourceClassName = resultSet.getString("ResourceClassName");

            if ((permissionsForResourceDomain = createPermissionsMap.get(resourceDomainName)) == null) {
               createPermissionsMap.put(resourceDomainName,
                                        permissionsForResourceDomain = new HashMap<>());
            }

            if ((permissionsForResourceClass = permissionsForResourceDomain.get(resourceClassName)) == null) {
               permissionsForResourceDomain.put(resourceClassName,
                                                permissionsForResourceClass = new HashSet<>());
            }

            permissionsForResourceClass.add(getResourceCreatePostCreatePermission(resultSet));
         }
         resultSet.close();

         return createPermissionsMap;
      }
      catch (SQLException e) {
         throw new RuntimeException(e);
      }
      finally {
         closeStatement(statement);
      }
   }

   @Override
   public void removeAllResourceCreatePostCreatePermissions(SQLConnection connection,
                                                            Id<DomainId> accessedDomainId) {
      SQLStatement statement = null;
      try {
         // chose strategy to perform recursive delete based on sql profile
         if (sqlProfile.isRecursiveDeleteEnabled()) {
            // prepare the standard recursive delete statement for domain and its children
            statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourceCreatePermissionPostCreate_withDescendants_BY_AccessedDomainId);

            // revoke any existing create non-system permissions any accessor has to this domain + any resource class
            statement.setResourceDomainId(1, accessedDomainId);
            statement.executeUpdate();
         }
         else {
            // DBMS doesn't support recursive deletion, so we have to remove domain's children's accessors first

            // get descendant domain Ids
            statement = connection.prepareStatement(sqlStrings.SQL_findInDomain_DescendantResourceDomainID_BY_DomainID_ORDERBY_DomainLevel);
            statement.setResourceDomainId(1, accessedDomainId);
            SQLResult resultSet = statement.executeQuery();

            List<Id<DomainId>> descendantDomainIds = new ArrayList<>();

            while (resultSet.next()) {
               descendantDomainIds.add(resultSet.getResourceDomainId("DomainId"));
            }
            closeStatement(statement);

            // delete domains' accessors (in reverse order of domainLevel, to preserve FK constraints)
            statement = connection.prepareStatement(sqlStrings.SQL_removeInGrantResourceCreatePermissionPostCreate_BY_AccessedDomainId);

            for (int i=descendantDomainIds.size()-1; i >= 0; i--) {
               statement.setResourceDomainId(1, descendantDomainIds.get(i));
               statement.executeUpdate();
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
