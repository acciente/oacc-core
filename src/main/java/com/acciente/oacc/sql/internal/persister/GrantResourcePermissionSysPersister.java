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
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.util.Set;

public interface GrantResourcePermissionSysPersister {
   Set<Resource> getResourcesByResourceSysPermission(SQLConnection connection,
                                                     Resource accessorResource,
                                                     Id<ResourceClassId> resourceClassId,
                                                     ResourcePermission resourcePermission);

   Set<Resource> getResourcesByResourceSysPermission(SQLConnection connection,
                                                     Resource accessorResource,
                                                     Id<ResourceClassId> resourceClassId,
                                                     Id<DomainId> resourceDomainId,
                                                     ResourcePermission resourcePermission);

   Set<Resource> getAccessorResourcesByResourceSysPermission(SQLConnection connection,
                                                             Resource accessedResource,
                                                             Id<ResourceClassId> resourceClassId,
                                                             ResourcePermission resourcePermission);

   Set<ResourcePermission> getResourceSysPermissionsIncludeInherited(SQLConnection connection,
                                                                     Resource accessorResource,
                                                                     Resource accessedResource);

   Set<ResourcePermission> getResourceSysPermissions(SQLConnection connection,
                                                     Resource accessorResource,
                                                     Resource accessedResource);

   void addResourceSysPermissions(SQLConnection connection,
                                  Resource accessorResource,
                                  Resource accessedResource,
                                  Id<ResourceClassId> accessedResourceClassId,
                                  Set<ResourcePermission> requestedResourcePermissions,
                                  Resource grantorResource);

   void updateResourceSysPermissions(SQLConnection connection,
                                     Resource accessorResource,
                                     Resource accessedResource,
                                     Id<ResourceClassId> accessedResourceClassId,
                                     Set<ResourcePermission> requestedResourcePermissions,
                                     Resource grantorResource);

   void removeAllResourceSysPermissionsAsAccessorOrAccessed(SQLConnection connection,
                                                            Resource resource);

   void removeResourceSysPermissions(SQLConnection connection,
                                     Resource accessorResource,
                                     Resource accessedResource);

   void removeResourceSysPermissions(SQLConnection connection,
                                     Resource accessorResource,
                                     Resource accessedResource,
                                     Id<ResourceClassId> accessedResourceClassId,
                                     Set<ResourcePermission> requestedResourcePermissions);
}
