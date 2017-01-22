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

public class ResourceClassInfo implements Serializable {
   private static final long serialVersionUID = 1L;

   private final String  resourceClassName;
   private final boolean authenticatable;
   private final boolean unauthenticatedCreateAllowed;

   public ResourceClassInfo(String resourceClassName,
                            boolean authenticatable,
                            boolean unauthenticatedCreateAllowed) {
      this.resourceClassName = resourceClassName;
      this.authenticatable = authenticatable;
      this.unauthenticatedCreateAllowed = unauthenticatedCreateAllowed;
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

   @Override
   public boolean equals(Object other) {
      if (this == other) {
         return true;
      }
      if (other == null || getClass() != other.getClass()) {
         return false;
      }

      ResourceClassInfo otherResourceClassInfo = (ResourceClassInfo) other;

      if (authenticatable != otherResourceClassInfo.authenticatable) {
         return false;
      }
      if (unauthenticatedCreateAllowed != otherResourceClassInfo.unauthenticatedCreateAllowed) {
         return false;
      }
      if (!resourceClassName.equals(otherResourceClassInfo.resourceClassName)) {
         return false;
      }

      return true;
   }

   @Override
   public int hashCode() {
      int result = resourceClassName.hashCode();
      result = 31 * result + (authenticatable ? 1 : 0);
      result = 31 * result + (unauthenticatedCreateAllowed ? 1 : 0);
      return result;
   }
}
