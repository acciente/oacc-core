/*
 * Copyright 2009-2015, Acciente LLC
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
package com.acciente.oacc;

import java.io.Serializable;

public class Resources {
   public static Resource getInstance(long resourceId) {
      return new ResourceImpl(resourceId, null);
   }

   public static Resource getInstance(long resourceId, String externalId) {
      return new ResourceImpl(resourceId, externalId);
   }

   public static Resource getInstance(String externalId) {
      return new ResourceImpl(externalId);
   }

   private static class ResourceImpl implements Resource, Serializable {
      private static final long serialVersionUID = 1L;

      private final Long resourceId;
      private final String externalId;

      private ResourceImpl(long resourceId,
                           String externalId) {
         this.resourceId = resourceId;
         this.externalId = externalId;
      }

      private ResourceImpl(String externalId) {
         this.resourceId = null;
         this.externalId = externalId;
      }

      @Override
      public Long getId() {
         return resourceId;
      }

      @Override
      public String getExternalId() {
         return externalId;
      }

      @Override
      public boolean equals(Object other) {
         if (this == other) {
            return true;
         }
         if (other == null || getClass() != other.getClass()) {
            return false;
         }

         ResourceImpl otherResource = (ResourceImpl) other;

         if (!resourceId.equals(otherResource.resourceId)) {
            return false;
         }

         return true;
      }

      @Override
      public int hashCode() {
         return resourceId.hashCode();
      }

      @Override
      /**
       * desired output:
       *                    | externalId != null       | externalId == null
       * -------------------|--------------------------|--------------------
       * resourceId != null | R(_rId_, extId: _extId_) | R(_rId_)
       * resourceId == null | R(extId: _extId_)        | R(_rId_, extId: _extId_)
       */
      public String toString() {
         if (resourceId != null && externalId == null) {
            return "R(" + String.valueOf(resourceId) + ")";
         }

         if (resourceId == null && externalId != null) {
            return "R(extId: " + externalId + ")";
         }

         return "R(" + String.valueOf(resourceId) + ", extId: " + externalId + ")";
      }
   }
}
