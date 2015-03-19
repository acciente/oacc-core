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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class NotAuthorizedException extends AuthorizationException {
   public NotAuthorizedException(String message) {
      super(message);
   }

   public NotAuthorizedException(String message, Throwable cause) {
      super(message, cause);
   }

   public NotAuthorizedException(Throwable cause) {
      super(cause);
   }

   // custom constructors to help craft uniform error messages
   public NotAuthorizedException(Resource accessorResource, String action) {
      super("Resource " + String.valueOf(accessorResource)
                  + " is not authorized to " + action);
   }

   public NotAuthorizedException(Resource accessorResource, String action, Resource accessedResource) {
      super("Resource " + String.valueOf(accessorResource)
                  + " is not authorized to " + action
                  + " resource " + String.valueOf(accessedResource));
   }

   public NotAuthorizedException(Resource accessorResource,
                                 DomainCreatePermission domainCreatePermission,
                                 DomainCreatePermission... domainCreatePermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have domain create permission(s) " + toString(domainCreatePermission,
                                                                             domainCreatePermissions));
   }

   public NotAuthorizedException(Resource accessorResource,
                                 String domainName,
                                 DomainPermission domainPermission,
                                 DomainPermission... domainPermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have domain permission(s) " + toString(domainPermission, domainPermissions)
                  + " on domain " + domainName);
   }

   public NotAuthorizedException(Resource accessorResource,
                                 DomainPermission domainPermission,
                                 DomainPermission... domainPermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " is not authorized to receive domain permission(s) " + toString(domainPermission, domainPermissions)
                  + " after creating a domain");
   }

   public NotAuthorizedException(Resource accessorResource,
                                 ResourceCreatePermission resourceCreatePermission,
                                 ResourceCreatePermission... resourceCreatePermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have resource create permission(s) " + toString(resourceCreatePermission,
                                                                               resourceCreatePermissions));
   }

   public NotAuthorizedException(Resource accessorResource,
                                 Resource accessedResource,
                                 ResourcePermission resourcePermission,
                                 ResourcePermission... resourcePermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have permission(s) " + toString(resourcePermission, resourcePermissions)
                  + " on resource " + String.valueOf(accessedResource));
   }

   public NotAuthorizedException(Resource accessorResource,
                                 String resourceClassName,
                                 String domainName,
                                 ResourcePermission resourcePermission,
                                 ResourcePermission... resourcePermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have global permission(s) " + toString(resourcePermission, resourcePermissions)
                  + " on resources of class " + resourceClassName
                  + " in domain " + domainName);
   }

   /**
    * Returns a String representation of the specified vararg sequence with a mandatory first element.
    *
    * <pre><code>
    *    first | others    | result*
    *   -------|-----------|--------
    *    null  | []        | [null]
    *    null  | null      | [null, null]
    *    a     | []        | [a]
    *    a     | null      | [a, null]
    *    a     | [b, a]    | [a, b, a]
    *    a     | [b, null] | [a, b, null]
    * </code></pre>
    * (*) the returned String representation will not guarantee any order of elements and will not de-duplicate
    */
   @SafeVarargs
   public static <T> String toString(T first, T... others) {
      List<T> resultList;

      if (others == null) {
         resultList = new ArrayList<>(2);
         resultList.add(null);
      }
      else {
         resultList = new ArrayList<>(others.length + 1);
         Collections.addAll(resultList, others);
      }

      resultList.add(first);

      return resultList.toString();
   }
}