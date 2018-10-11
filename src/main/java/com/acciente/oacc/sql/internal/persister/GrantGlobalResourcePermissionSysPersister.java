/*
 * Copyright 2009-2018, Acciente LLC
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

import java.util.Map;
import java.util.Set;

public interface GrantGlobalResourcePermissionSysPersister {
   Set<Resource> getResourcesByGlobalSysPermission(SQLConnection connection,
                                                   Resource accessorResource,
                                                   Id<ResourceClassId> resourceClassId,
                                                   ResourcePermission resourcePermission);

   Set<Resource> getResourcesByGlobalSysPermission(SQLConnection connection,
                                                   Resource accessorResource,
                                                   Id<ResourceClassId> resourceClassId,
                                                   Id<DomainId> resourceDomainId,
                                                   ResourcePermission resourcePermission);

   Set<ResourcePermission> getGlobalSysPermissionsIncludeInherited(SQLConnection connection,
                                                                   Resource accessorResource,
                                                                   Id<ResourceClassId> resourceClassId,
                                                                   Id<DomainId> resourceDomainId);

   Set<ResourcePermission> getGlobalSysPermissions(SQLConnection connection,
                                                   Resource accessorResource,
                                                   Id<ResourceClassId> resourceClassId,
                                                   Id<DomainId> resourceDomainId);

   Map<String, Map<String, Set<ResourcePermission>>> getGlobalSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                             Resource accessorResource);

   Map<String, Map<String, Set<ResourcePermission>>> getGlobalSysPermissions(SQLConnection connection,
                                                                             Resource accessorResource);

   void addGlobalSysPermissions(SQLConnection connection,
                                Resource accessorResource,
                                Id<ResourceClassId> accessedResourceClassId,
                                Id<DomainId> accessedResourceDomainId,
                                Set<ResourcePermission> requestedResourcePermissions,
                                Resource grantorResource);

   void updateGlobalSysPermissions(SQLConnection connection,
                                   Resource accessorResource,
                                   Id<ResourceClassId> accessedResourceClassId,
                                   Id<DomainId> accessedResourceDomainId,
                                   Set<ResourcePermission> requestedResourcePermissions,
                                   Resource grantorResource);

   void removeAllGlobalSysPermissions(SQLConnection connection,
                                      Resource accessorResource);

   void removeAllGlobalSysPermissions(SQLConnection connection,
                                      Id<DomainId> accessedDomainId);

   void removeGlobalSysPermissions(SQLConnection connection,
                                   Resource accessorResource,
                                   Id<ResourceClassId> accessedResourceClassId,
                                   Id<DomainId> accessedResourceDomainId);

   void removeGlobalSysPermissions(SQLConnection connection,
                                   Resource accessorResource,
                                   Id<ResourceClassId> accessedResourceClassId,
                                   Id<DomainId> accessedResourceDomainId,
                                   Set<ResourcePermission> requestedResourcePermissions);
}
