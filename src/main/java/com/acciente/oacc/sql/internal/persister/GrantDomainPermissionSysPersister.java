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

import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.Resource;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

import java.util.Map;
import java.util.Set;

public interface GrantDomainPermissionSysPersister {
   Set<Resource> getResourcesByDomainSuperUserPermission(SQLConnection connection,
                                                         Resource accessorResource,
                                                         Id<ResourceClassId> resourceClassId);

   Set<Resource> getResourcesByDomainSuperUserPermission(SQLConnection connection,
                                                         Resource accessorResource,
                                                         Id<ResourceClassId> resourceClassId,
                                                         Id<DomainId> resourceDomainId);

   Set<DomainPermission> getDomainSysPermissionsIncludeInherited(SQLConnection connection,
                                                                 Resource accessorResource,
                                                                 Id<DomainId> resourceDomainId);

   Set<DomainPermission> getDomainSysPermissions(SQLConnection connection,
                                                 Resource accessorResource,
                                                 Id<DomainId> resourceDomainId);

   Map<String, Set<DomainPermission>> getDomainSysPermissionsIncludeInherited(SQLConnection connection,
                                                                              Resource accessorResource);

   Map<String, Set<DomainPermission>> getDomainSysPermissions(SQLConnection connection,
                                                              Resource accessorResource);

   void addDomainSysPermissions(SQLConnection connection,
                                Resource accessorResource,
                                Resource grantorResource,
                                Id<DomainId> resourceDomainId,
                                Set<DomainPermission> requestedDomainPermissions);

   void updateDomainSysPermissions(SQLConnection connection,
                                   Resource accessorResource,
                                   Resource grantorResource,
                                   Id<DomainId> resourceDomainId,
                                   Set<DomainPermission> requestedDomainPermissions);

   void removeAllDomainSysPermissions(SQLConnection connection,
                                      Resource accessorResource);

   void removeAllDomainSysPermissions(SQLConnection connection,
                                      Id<DomainId> domainId);

   void removeDomainSysPermissions(SQLConnection connection,
                                   Resource accessorResource,
                                   Id<DomainId> resourceDomainId);

   void removeDomainSysPermissions(SQLConnection connection,
                                   Resource accessorResource,
                                   Id<DomainId> resourceDomainId,
                                   Set<DomainPermission> requestedDomainPermissions);
}
