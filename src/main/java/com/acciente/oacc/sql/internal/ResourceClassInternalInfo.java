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
package com.acciente.oacc.sql.internal;

import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;

public class ResourceClassInternalInfo {
   private final long    resourceClassId;
   private final String  resourceClassName;
   private final boolean authenticatable;
   private final boolean unauthenticatedCreateAllowed;

   public ResourceClassInternalInfo(Id<ResourceClassId> resourceClassId,
                                    String resourceClassName,
                                    boolean authenticatable,
                                    boolean unauthenticatedCreateAllowed) {
      this.resourceClassId = resourceClassId.getValue();
      this.resourceClassName = resourceClassName;
      this.authenticatable = authenticatable;
      this.unauthenticatedCreateAllowed = unauthenticatedCreateAllowed;
   }

   public long getResourceClassId() {
      return resourceClassId;
   }

   public String getResourceClassName() {
      return resourceClassName;
   }

   public boolean isAuthenticatable() {
      return authenticatable;
   }

   public boolean isUnauthenticatedCreateAllowed() {
      return unauthenticatedCreateAllowed;
   }
}
