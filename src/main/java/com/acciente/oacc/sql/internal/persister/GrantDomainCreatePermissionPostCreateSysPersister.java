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

import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.Resource;

import java.util.Set;

public interface GrantDomainCreatePermissionPostCreateSysPersister {
   Set<DomainCreatePermission> getDomainCreatePostCreateSysPermissionsIncludeInherited(SQLConnection connection,
                                                                                       Resource accessorResource);

   Set<DomainCreatePermission> getDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                                       Resource accessorResource);

   void removeDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                   Resource accessorResource);

   void removeDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                   Resource accessorResource,
                                                   Set<DomainCreatePermission> domainCreatePermissions);

   void addDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                Resource accessorResource,
                                                Resource grantorResource,
                                                Set<DomainCreatePermission> domainCreatePermissions);

   void updateDomainCreatePostCreateSysPermissions(SQLConnection connection,
                                                   Resource accessorResource,
                                                   Resource grantorResource,
                                                   Set<DomainCreatePermission> domainCreatePermissions);
}
