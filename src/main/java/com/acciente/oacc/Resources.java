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

         if (resourceId != null ? !resourceId.equals(otherResource.resourceId) : otherResource.resourceId != null) {
            return false;
         }
         return !(externalId != null ? !externalId.equals(otherResource.externalId) : otherResource.externalId != null);
      }

      @Override
      public int hashCode() {
         int result = resourceId != null ? resourceId.hashCode() : 0;
         result = 31 * result + (externalId != null ? externalId.hashCode() : 0);
         return result;
      }

      @Override
      /**
       * sample output:
       *                    | externalId != null                    | externalId == null
       * -------------------|---------------------------------------|--------------------
       * resourceId != null | {resourceId: 1234, externalId: "007"} | {resourceId: 1234}
       * resourceId == null | {externalId: "007"}                   | {}
       */
      public String toString() {
         if (resourceId != null && externalId != null) {
            return "{resourceId: " + String.valueOf(resourceId) + ", externalId: \""  + externalId + "\"}";
         }

         if (resourceId != null) {
            return "{resourceId: " + String.valueOf(resourceId) + "}";
         }

         if (externalId != null) {
            return "{externalId: \""  + externalId + "\"}";
         }

         return "{}";
      }
   }
}
