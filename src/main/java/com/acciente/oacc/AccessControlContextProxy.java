/*
 * Copyright 2009-2014, Acciente LLC
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

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * AccessControlContextProxy
 * <p/>
 * This class is intended to be used as a proxy on an instance of the class that implements
 * AccessControlContext to restrict access to the methods defined in the
 * AccessControlContextProxy interface.
 *
 */
public class AccessControlContextProxy implements AccessControlContext {
   private AccessControlContext accessControlContext;

   @Override
   public void authenticate(Resource resource, Credentials credentials) throws AccessControlException {
      accessControlContext.authenticate(resource, credentials);
   }

   @Override
   public void authenticate(Resource resource) throws AccessControlException {
      accessControlContext.authenticate(resource);
   }

   @Override
   public void unauthenticate() throws AccessControlException {
      accessControlContext.unauthenticate();
   }

   @Override
   public void impersonate(Resource resource) throws AccessControlException {
      accessControlContext.impersonate(resource);
   }

   @Override
   public void unimpersonate() throws AccessControlException {
      accessControlContext.unimpersonate();
   }

   @Override
   public void setCredentials(Resource resource, Credentials newCredentials) throws AccessControlException {
      accessControlContext.setCredentials(resource, newCredentials);
   }

   @Override
   public void assertGlobalResourcePermission(String resourceClassName,
                                              ResourcePermission resourcePermission) throws AccessControlException {
      accessControlContext.assertGlobalResourcePermission(resourceClassName, resourcePermission);
   }

   @Override
   public void assertGlobalResourcePermission(String resourceClassName,
                                              ResourcePermission resourcePermission,
                                              String domainName) throws AccessControlException {
      accessControlContext.assertGlobalResourcePermission(resourceClassName, resourcePermission, domainName);
   }

   @Override
   public void assertResourcePermission(Resource accessedResource,
                                        ResourcePermission resourcePermission) throws AccessControlException {
      accessControlContext.assertResourcePermission(accessedResource, resourcePermission);
   }

   @Override
   public void assertResourcePermission(Resource accessorResource,
                                        Resource accessedResource,
                                        ResourcePermission resourcePermission) throws AccessControlException {
      accessControlContext.assertResourcePermission(accessorResource, accessedResource, resourcePermission);
   }

   @Override
   public void assertPostCreateResourcePermission(String resourceClassName,
                                                  ResourcePermission resourcePermission) throws AccessControlException {
      accessControlContext.assertPostCreateResourcePermission(resourceClassName, resourcePermission);
   }

   @Override
   public void assertPostCreateResourcePermission(String resourceClassName,
                                                  ResourcePermission resourcePermission,
                                                  String domainName) throws AccessControlException {
      accessControlContext.assertPostCreateResourcePermission(resourceClassName, resourcePermission, domainName);
   }

   @Override
   public String getDomainNameByResource(Resource resource) throws AccessControlException {
      return accessControlContext.getDomainNameByResource(resource);
   }

   @Override
   public Set<String> getDomainDescendants(String domainName) throws AccessControlException {
      return accessControlContext.getDomainDescendants(domainName);
   }

   @Override
   public ResourceClassInfo getResourceClassInfo(String resourceClassName) throws AccessControlException {
      return accessControlContext.getResourceClassInfo(resourceClassName);
   }

   @Override
   public ResourceClassInfo getResourceClassInfoByResource(Resource resource) throws AccessControlException {
      return accessControlContext.getResourceClassInfoByResource(resource);
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(String resourceClassName,
                                                         ResourcePermission resourcePermission) throws AccessControlException {
      return accessControlContext.getResourcesByResourcePermission(resourceClassName, resourcePermission);
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(Resource accessorResource,
                                                         String resourceClassName,
                                                         ResourcePermission resourcePermission) throws AccessControlException {
      return accessControlContext.getResourcesByResourcePermission(accessorResource, resourceClassName, resourcePermission);
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(String resourceClassName,
                                                         ResourcePermission resourcePermission,
                                                         String domainName) throws AccessControlException {
      return accessControlContext.getResourcesByResourcePermission(resourceClassName, resourcePermission, domainName);
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(Resource accessorResource,
                                                         String resourceClassName,
                                                         ResourcePermission resourcePermission,
                                                         String domainName) throws AccessControlException {
      return accessControlContext.getResourcesByResourcePermission(accessorResource, resourceClassName, resourcePermission, domainName);
   }

   @Override
   public Set<Resource> getAccessorResourcesByResourcePermission(Resource accessedResource,
                                                                 String resourceClassName,
                                                                 ResourcePermission resourcePermission) throws AccessControlException {
      return accessControlContext.getAccessorResourcesByResourcePermission(accessedResource, resourceClassName, resourcePermission);
   }

   @Override
   public Resource getAuthenticatedResource() throws AccessControlException {
      return accessControlContext.getAuthenticatedResource();
   }

   @Override
   public Resource getSessionResource() throws AccessControlException {
      return accessControlContext.getSessionResource();
   }

   @Override
   public void createResourceClass(String resourceClassName,
                                   boolean authenticatable,
                                   boolean unuthenticatedCreateAllowed) throws AccessControlException {
      accessControlContext.createResourceClass(resourceClassName, authenticatable, unuthenticatedCreateAllowed);
   }

   @Override
   public void createResourcePermission(String resourceClassName, String permissionName) throws AccessControlException {
      accessControlContext.createResourcePermission(resourceClassName, permissionName);
   }

   @Override
   public void createDomain(String domainName) throws AccessControlException {
      accessControlContext.createDomain(domainName);
   }

   @Override
   public void createDomain(String domainName, String parentDomainName) throws AccessControlException {
      accessControlContext.createDomain(domainName, parentDomainName);
   }

   @Override
   public Resource createResource(String resourceClassName) throws AccessControlException {
      return accessControlContext.createResource(resourceClassName);
   }

   @Override
   public Resource createResource(String resourceClassName, String domainName) throws AccessControlException {
      return accessControlContext.createResource(resourceClassName, domainName);
   }

   @Override
   public Resource createResource(String resourceClassName, Credentials credentials) throws AccessControlException {
      return accessControlContext.createResource(resourceClassName, credentials);
   }

   @Override
   public Resource createResource(String resourceClassName,
                                  String domainName,
                                  Credentials credentials) throws AccessControlException {
      return accessControlContext.createResource(resourceClassName, domainName, credentials);
   }

   @Override
   public void setDomainCreatePermissions(Resource accessorResource,
                                          Set<DomainCreatePermission> domainCreatePermissions) throws AccessControlException {
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);
   }

   @Override
   public Set<DomainCreatePermission> getDomainCreatePermissions(Resource accessorResource) throws AccessControlException {
      return accessControlContext.getDomainCreatePermissions(accessorResource);
   }

   @Override
   public Set<DomainCreatePermission> getEffectiveDomainCreatePermissions(Resource accessorResource) throws AccessControlException {
      return accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
   }

   @Override
   public void setDomainPermissions(Resource accessorResource,
                                    String domainName,
                                    Set<DomainPermission> domainPermissions) throws AccessControlException {
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions);
   }

   @Override
   public Set<DomainPermission> getEffectiveDomainPermissions(Resource accessorResource,
                                                              String domainName) throws AccessControlException {
      return accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
   }

   @Override
   public Map<String, Set<DomainPermission>> getEffectiveDomainPermissionsMap(Resource accessorResource) throws AccessControlException {
      return accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
   }

   @Override
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions,
                                            String domainName) throws AccessControlException {
      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, resourceCreatePermissions, domainName);
   }

   @Override
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName,
                                                                              String domainName) throws AccessControlException {
      return accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
   }

   @Override
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions) throws AccessControlException {
      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, resourceCreatePermissions);
   }

   @Override
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName) throws AccessControlException {
      return accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
   }

   @Override
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getEffectiveResourceCreatePermissionsMap(Resource accessorResource) throws AccessControlException {
      return accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
   }

   @Override
   public void setResourcePermissions(Resource accessorResource,
                                      Resource accessedResource,
                                      Set<ResourcePermission> resourcePermissions) throws AccessControlException {
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);
   }

   @Override
   public Set<ResourcePermission> getEffectiveResourcePermissions(Resource accessorResource,
                                                                  Resource accessedResource) throws AccessControlException {
      return accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
   }

   @Override
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions,
                                            String domainName) throws AccessControlException {
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, resourcePermissions, domainName);
   }

   @Override
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName,
                                                                        String domainName) throws AccessControlException {
      return accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
   }

   @Override
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions) throws AccessControlException {
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, resourcePermissions);
   }

   @Override
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName) throws AccessControlException {
      return accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
   }

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getEffectiveGlobalResourcePermissionsMap(Resource accessorResource) throws AccessControlException {
      return accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
   }

   @Override
   public List<String> getResourceClassNames() throws AccessControlException {
      return accessControlContext.getResourceClassNames();
   }

   @Override
   public List<String> getResourcePermissionNames(String resourceClassName) throws AccessControlException {
      return accessControlContext.getResourcePermissionNames(resourceClassName);
   }
}
