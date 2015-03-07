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

import java.util.Arrays;

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

   public NotAuthorizedException(Resource accessorResource, DomainCreatePermission... domainCreatePermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have domain create permission(s) " + Arrays.asList(domainCreatePermissions));
   }

   public NotAuthorizedException(Resource accessorResource, String domainName, DomainPermission... domainPermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have domain permission(s) " + Arrays.asList(domainPermissions)
                  + " on domain " + domainName);
   }

   public NotAuthorizedException(Resource accessorResource, ResourceCreatePermission... resourceCreatePermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have resource create permission(s) " + Arrays.asList(resourceCreatePermissions));
   }

   public NotAuthorizedException(Resource accessorResource,
                                 Resource accessedResource,
                                 ResourcePermission... resourcePermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have permission(s) " + Arrays.asList(resourcePermissions)
                  + " on resource " + String.valueOf(accessedResource));
   }

   public NotAuthorizedException(Resource accessorResource,
                                 String resourceClassName,
                                 String domainName,
                                 ResourcePermission... resourcePermissions) {
      super("Resource " + String.valueOf(accessorResource)
                  + " does not have global permission(s) " + Arrays.asList(resourcePermissions)
                  + " on resources of class " + resourceClassName
                  + " in domain " + domainName);
   }
}