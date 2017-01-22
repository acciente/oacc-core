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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class NotAuthorizedException extends AuthorizationException {
   private static final long serialVersionUID = 1L;

   public NotAuthorizedException(String message) {
      super(message);
   }

   public NotAuthorizedException(String message, Throwable cause) {
      super(message, cause);
   }

   public NotAuthorizedException(Throwable cause) {
      super(cause);
   }

   // custom static factory methods to help craft uniform error messages
   public static NotAuthorizedException newInstanceForAction(Resource accessorResource,
                                                             String action) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " is not authorized to "
                                              + action);
   }

   public static NotAuthorizedException newInstanceForActionOnResource(Resource accessorResource,
                                                                       String action,
                                                                       Resource accessedResource) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " is not authorized to "
                                              + action
                                              + " resource "
                                              + String.valueOf(accessedResource));
   }

   public static NotAuthorizedException newInstanceForDomainCreatePermissions(Resource accessorResource,
                                                                              Set<DomainCreatePermission> domainCreatePermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have domain create permission(s) "
                                              + String.valueOf(domainCreatePermissions));
   }

   public static NotAuthorizedException newInstanceForDomainCreatePermissions(Resource accessorResource,
                                                                              DomainCreatePermission domainCreatePermission,
                                                                              DomainCreatePermission... domainCreatePermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have domain create permission(s) "
                                              + toString(domainCreatePermission, domainCreatePermissions));
   }

   public static NotAuthorizedException newInstanceForDomainPermissions(Resource accessorResource,
                                                                        String domainName,
                                                                        Set<DomainPermission> domainPermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have domain permission(s) "
                                              + String.valueOf(domainPermissions)
                                              + " on domain "
                                              + domainName);
   }

   public static NotAuthorizedException newInstanceForDomainPermissions(Resource accessorResource,
                                                                        String domainName,
                                                                        DomainPermission domainPermission,
                                                                        DomainPermission... domainPermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have domain permission(s) "
                                              + toString(domainPermission, domainPermissions)
                                              + " on domain "
                                              + domainName);
   }

   public static NotAuthorizedException newInstanceForPostCreateDomainPermissions(Resource accessorResource,
                                                                                  Set<DomainPermission> domainPermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " is not authorized to receive "
                                              + String.valueOf(domainPermissions)
                                              + " domain permission(s) after creating a domain");
   }

   public static NotAuthorizedException newInstanceForPostCreateDomainPermissions(Resource accessorResource,
                                                                                  DomainPermission domainPermission,
                                                                                  DomainPermission... domainPermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " is not authorized to receive "
                                              + toString(domainPermission, domainPermissions)
                                              + " domain permission(s) after creating a domain");
   }

   public static NotAuthorizedException newInstanceForResourceCreatePermissions(Resource accessorResource,
                                                                                Set<ResourceCreatePermission> resourceCreatePermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have resource create permission(s) "
                                              + String.valueOf(resourceCreatePermissions));
   }

   public static NotAuthorizedException newInstanceForResourceCreatePermissions(Resource accessorResource,
                                                                                ResourceCreatePermission resourceCreatePermission,
                                                                                ResourceCreatePermission... resourceCreatePermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have resource create permission(s) "
                                              + toString(resourceCreatePermission, resourceCreatePermissions));
   }

   public static NotAuthorizedException newInstanceForResourcePermissions(Resource accessorResource,
                                                                          Resource accessedResource,
                                                                          Set<ResourcePermission> resourcePermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have permission(s) "
                                              + String.valueOf(resourcePermissions)
                                              + " on resource "
                                              + String.valueOf(accessedResource));
   }

   public static NotAuthorizedException newInstanceForResourcePermissions(Resource accessorResource,
                                                                          Resource accessedResource,
                                                                          ResourcePermission resourcePermission,
                                                                          ResourcePermission... resourcePermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have permission(s) "
                                              + toString(resourcePermission, resourcePermissions)
                                              + " on resource "
                                              + String.valueOf(accessedResource));
   }

   public static NotAuthorizedException newInstanceForGlobalResourcePermissions(Resource accessorResource,
                                                                                String resourceClassName,
                                                                                String domainName,
                                                                                Set<ResourcePermission> resourcePermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have global permission(s) "
                                              + String.valueOf(resourcePermissions)
                                              + " on resources of class "
                                              + resourceClassName
                                              + " in domain "
                                              + domainName);
   }

   public static NotAuthorizedException newInstanceForGlobalResourcePermissions(Resource accessorResource,
                                                                                String resourceClassName,
                                                                                String domainName,
                                                                                ResourcePermission resourcePermission,
                                                                                ResourcePermission... resourcePermissions) {
      return new NotAuthorizedException("Resource "
                                              + String.valueOf(accessorResource)
                                              + " does not have global permission(s) "
                                              + toString(resourcePermission, resourcePermissions)
                                              + " on resources of class "
                                              + resourceClassName
                                              + " in domain "
                                              + domainName);
   }

   public static NotAuthorizedException newInstanceForPostCreateResourcePermissions(Resource accessorResource,
                                                                                    String resourceClassName,
                                                                                    String domainName,
                                                                                    Set<ResourcePermission> resourcePermissions) {
      return new NotAuthorizedException(accessorResource
                                              + "receive "
                                              + String.valueOf(resourcePermissions)
                                              + " permission(s) after creating a "
                                              + resourceClassName
                                              + " resource in domain "
                                              + domainName);
   }

   public static NotAuthorizedException newInstanceForPostCreateResourcePermissions(Resource accessorResource,
                                                                                    String resourceClassName,
                                                                                    String domainName,
                                                                                    ResourcePermission resourcePermission,
                                                                                    ResourcePermission... resourcePermissions) {
      return new NotAuthorizedException(accessorResource
                                              + "receive "
                                              + toString(resourcePermission, resourcePermissions)
                                              + " permission(s) after creating a "
                                              + resourceClassName
                                              + " resource in domain "
                                              + domainName);
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
   private static <T> String toString(T first, T... others) {
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