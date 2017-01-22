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
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;

public interface ResourcePersister {
   void verifyResourceExists(SQLConnection connection,
                             Resource resource);

   Resource createResource(SQLConnection connection,
                           Id<ResourceClassId> resourceClassId,
                           Id<DomainId> resourceDomainId,
                           String externalId);

   Resource setExternalId(SQLConnection connection,
                          Id<ResourceId> resourceId,
                          String externalId);

   void deleteResource(SQLConnection connection,
                       Resource resource);

   Id<DomainId> getDomainIdByResource(SQLConnection connection,
                                      Resource resource);

   Id<ResourceId> getNextResourceId(SQLConnection connection);

   boolean isDomainEmpty(SQLConnection connection,
                         Id<DomainId> resourceDomainId);

   Resource resolveResourceByExternalId(SQLConnection connection,
                                        String externalId);

   Resource resolveResourceByResourceId(SQLConnection connection,
                                        Resource resource);
}
