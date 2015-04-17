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
   public void authenticate(Resource resource, Credentials credentials) {
      accessControlContext.authenticate(resource, credentials);
   }

   @Override
   public void authenticate(Resource resource) {
      accessControlContext.authenticate(resource);
   }

   @Override
   public void unauthenticate() {
      accessControlContext.unauthenticate();
   }

   @Override
   public void impersonate(Resource resource) {
      accessControlContext.impersonate(resource);
   }

   @Override
   public void unimpersonate() {
      accessControlContext.unimpersonate();
   }

   @Override
   public void setCredentials(Resource resource, Credentials newCredentials) {
      accessControlContext.setCredentials(resource, newCredentials);
   }

   @Override
   public void assertDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       DomainPermission domainPermission,
                                       DomainPermission... domainPermissions) {
      accessControlContext.assertDomainPermissions(accessorResource, domainName, domainPermission, domainPermissions);
   }

   @Override
   public void assertDomainPermissions(String domainName,
                                       DomainPermission domainPermission,
                                       DomainPermission... domainPermissions) {
      accessControlContext.assertDomainPermissions(domainName, domainPermission, domainPermissions);
   }

   @Override
   public boolean hasDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       DomainPermission domainPermission,
                                       DomainPermission... domainPermissions) {
      return accessControlContext.hasDomainPermissions(accessorResource, domainName, domainPermission, domainPermissions);
   }

   @Override
   public boolean hasDomainPermissions(String domainName,
                                       DomainPermission domainPermission,
                                       DomainPermission... domainPermissions) {
      return accessControlContext.hasDomainPermissions(domainName, domainPermission, domainPermissions);
   }

   @Override
   public void assertDomainCreatePermissions(Resource accessorResource,
                                             DomainCreatePermission domainCreatePermission,
                                             DomainCreatePermission... domainCreatePermissions) {
      accessControlContext.assertDomainCreatePermissions(accessorResource, domainCreatePermission, domainCreatePermissions);
   }

   @Override
   public void assertDomainCreatePermissions(DomainCreatePermission domainCreatePermission,
                                             DomainCreatePermission... domainCreatePermissions) {
      accessControlContext.assertDomainCreatePermissions(domainCreatePermission, domainCreatePermissions);
   }

   @Override
   public boolean hasDomainCreatePermissions(Resource accessorResource,
                                             DomainCreatePermission domainCreatePermission,
                                             DomainCreatePermission... domainCreatePermissions) {
      return accessControlContext.hasDomainCreatePermissions(accessorResource, domainCreatePermission, domainCreatePermissions);
   }

   @Override
   public boolean hasDomainCreatePermissions(DomainCreatePermission domainCreatePermission,
                                             DomainCreatePermission... domainCreatePermissions) {
      return accessControlContext.hasDomainCreatePermissions(domainCreatePermission, domainCreatePermissions);
   }

   @Override
   public void assertPostCreateDomainPermissions(Resource accessorResource,
                                                 DomainPermission domainPermission,
                                                 DomainPermission... domainPermissions) {
      accessControlContext.assertPostCreateDomainPermissions(accessorResource, domainPermission, domainPermissions);
   }

   @Override
   public void assertPostCreateDomainPermissions(DomainPermission domainPermission,
                                                 DomainPermission... domainPermissions) {
      accessControlContext.assertPostCreateDomainPermissions(domainPermission, domainPermissions);
   }

   @Override
   public boolean hasPostCreateDomainPermissions(Resource accessorResource,
                                                 DomainPermission domainPermission,
                                                 DomainPermission... domainPermissions) {
      return accessControlContext.hasPostCreateDomainPermissions(accessorResource, domainPermission, domainPermissions);
   }

   @Override
   public boolean hasPostCreateDomainPermissions(DomainPermission domainPermission,
                                                 DomainPermission... domainPermissions) {
      return accessControlContext.hasPostCreateDomainPermissions(domainPermission, domainPermissions);
   }

   @Override
   public void assertGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      accessControlContext.assertGlobalResourcePermissions(accessorResource, resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertGlobalResourcePermissions(String resourceClassName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      accessControlContext.assertGlobalResourcePermissions(resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      accessControlContext.assertGlobalResourcePermissions(accessorResource, resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertGlobalResourcePermissions(String resourceClassName,
                                               String domainName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      accessControlContext.assertGlobalResourcePermissions(resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      return accessControlContext.hasGlobalResourcePermissions(accessorResource, resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasGlobalResourcePermissions(String resourceClassName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      return accessControlContext.hasGlobalResourcePermissions(resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      return accessControlContext.hasGlobalResourcePermissions(accessorResource, resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasGlobalResourcePermissions(String resourceClassName,
                                               String domainName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      return accessControlContext.hasGlobalResourcePermissions(resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         ResourcePermission resourcePermission,
                                         ResourcePermission... resourcePermissions) {
      accessControlContext.assertResourcePermissions(accessorResource, accessedResource, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertResourcePermissions(Resource accessedResource,
                                         ResourcePermission resourcePermission,
                                         ResourcePermission... resourcePermissions) {
      accessControlContext.assertResourcePermissions(accessedResource, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         ResourcePermission resourcePermission,
                                         ResourcePermission... resourcePermissions) {
      return accessControlContext.hasResourcePermissions(accessorResource, accessedResource, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasResourcePermissions(Resource accessedResource,
                                         ResourcePermission resourcePermission,
                                         ResourcePermission... resourcePermissions) {
      return accessControlContext.hasResourcePermissions(accessedResource, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      accessControlContext.assertResourceCreatePermissions(accessorResource, resourceClassName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public void assertResourceCreatePermissions(String resourceClassName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      accessControlContext.assertResourceCreatePermissions(resourceClassName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public void assertResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      accessControlContext.assertResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public void assertResourceCreatePermissions(String resourceClassName,
                                               String domainName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      accessControlContext.assertResourceCreatePermissions(resourceClassName, domainName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public boolean hasResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      return accessControlContext.hasResourceCreatePermissions(accessorResource, resourceClassName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public boolean hasResourceCreatePermissions(String resourceClassName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      return accessControlContext.hasResourceCreatePermissions(resourceClassName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public boolean hasResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      return accessControlContext.hasResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public boolean hasResourceCreatePermissions(String resourceClassName,
                                               String domainName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      return accessControlContext.hasResourceCreatePermissions(resourceClassName, domainName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public void assertPostCreateResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      accessControlContext.assertPostCreateResourcePermissions(accessorResource, resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertPostCreateResourcePermissions(String resourceClassName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      accessControlContext.assertPostCreateResourcePermissions(resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertPostCreateResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   String domainName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      accessControlContext.assertPostCreateResourcePermissions(accessorResource, resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public void assertPostCreateResourcePermissions(String resourceClassName,
                                                   String domainName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      accessControlContext.assertPostCreateResourcePermissions(resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasPostCreateResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      return accessControlContext.hasPostCreateResourcePermissions(accessorResource, resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasPostCreateResourcePermissions(String resourceClassName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      return accessControlContext.hasPostCreateResourcePermissions(resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasPostCreateResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   String domainName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      return accessControlContext.hasPostCreateResourcePermissions(accessorResource, resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public boolean hasPostCreateResourcePermissions(String resourceClassName,
                                                   String domainName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      return accessControlContext.hasPostCreateResourcePermissions(resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public String getDomainNameByResource(Resource resource) {
      return accessControlContext.getDomainNameByResource(resource);
   }

   @Override
   public Set<String> getDomainDescendants(String domainName) {
      return accessControlContext.getDomainDescendants(domainName);
   }

   @Override
   public ResourceClassInfo getResourceClassInfo(String resourceClassName) {
      return accessControlContext.getResourceClassInfo(resourceClassName);
   }

   @Override
   public ResourceClassInfo getResourceClassInfoByResource(Resource resource) {
      return accessControlContext.getResourceClassInfoByResource(resource);
   }

   @Override
   public Set<Resource> getResourcesByResourcePermissions(String resourceClassName,
                                                          ResourcePermission resourcePermission,
                                                          ResourcePermission... resourcePermissions) {
      return accessControlContext.getResourcesByResourcePermissions(resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public Set<Resource> getResourcesByResourcePermissions(Resource accessorResource,
                                                          String resourceClassName,
                                                          ResourcePermission resourcePermission,
                                                          ResourcePermission... resourcePermissions) {
      return accessControlContext.getResourcesByResourcePermissions(accessorResource, resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public Set<Resource> getResourcesByResourcePermissionsAndDomain(String resourceClassName,
                                                                   String domainName,
                                                                   ResourcePermission resourcePermission,
                                                                   ResourcePermission... resourcePermissions) {
      return accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName, domainName, resourcePermission);
   }

   @Override
   public Set<Resource> getResourcesByResourcePermissionsAndDomain(Resource accessorResource,
                                                                   String resourceClassName,
                                                                   String domainName,
                                                                   ResourcePermission resourcePermission,
                                                                   ResourcePermission... resourcePermissions) {
      return accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource, resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public Set<Resource> getAccessorResourcesByResourcePermissions(Resource accessedResource,
                                                                  String resourceClassName,
                                                                  ResourcePermission resourcePermission,
                                                                  ResourcePermission... resourcePermissions) {
      return accessControlContext.getAccessorResourcesByResourcePermissions(accessedResource, resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public Resource getAuthenticatedResource() {
      return accessControlContext.getAuthenticatedResource();
   }

   @Override
   public Resource getSessionResource() {
      return accessControlContext.getSessionResource();
   }

   @Override
   public void createResourceClass(String resourceClassName,
                                   boolean authenticatable,
                                   boolean unauthenticatedCreateAllowed) {
      accessControlContext.createResourceClass(resourceClassName, authenticatable, unauthenticatedCreateAllowed);
   }

   @Override
   public void createResourcePermission(String resourceClassName, String permissionName) {
      accessControlContext.createResourcePermission(resourceClassName, permissionName);
   }

   @Override
   public void createDomain(String domainName) {
      accessControlContext.createDomain(domainName);
   }

   @Override
   public void createDomain(String domainName, String parentDomainName) {
      accessControlContext.createDomain(domainName, parentDomainName);
   }

   @Override
   public Resource createResource(String resourceClassName) {
      return accessControlContext.createResource(resourceClassName);
   }

   @Override
   public Resource createResource(String resourceClassName, String domainName) {
      return accessControlContext.createResource(resourceClassName, domainName);
   }

   @Override
   public Resource createResource(String resourceClassName, Credentials credentials) {
      return accessControlContext.createResource(resourceClassName, credentials);
   }

   @Override
   public Resource createResource(String resourceClassName,
                                  String domainName,
                                  Credentials credentials) {
      return accessControlContext.createResource(resourceClassName, domainName, credentials);
   }

   @Override
   public void setDomainCreatePermissions(Resource accessorResource,
                                          Set<DomainCreatePermission> domainCreatePermissions) {
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);
   }

   @Override
   public void grantDomainCreatePermissions(Resource accessorResource,
                                            DomainCreatePermission domainCreatePermission,
                                            DomainCreatePermission... domainCreatePermissions) {
      accessControlContext.grantDomainCreatePermissions(accessorResource, domainCreatePermission, domainCreatePermissions);
   }

   @Override
   public void revokeDomainCreatePermissions(Resource accessorResource,
                                             DomainCreatePermission domainCreatePermission,
                                             DomainCreatePermission... domainCreatePermissions) {
      accessControlContext.revokeDomainCreatePermissions(accessorResource, domainCreatePermission, domainCreatePermissions);
   }

   @Override
   public Set<DomainCreatePermission> getDomainCreatePermissions(Resource accessorResource) {
      return accessControlContext.getDomainCreatePermissions(accessorResource);
   }

   @Override
   public Set<DomainCreatePermission> getEffectiveDomainCreatePermissions(Resource accessorResource) {
      return accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
   }

   @Override
   public void setDomainPermissions(Resource accessorResource,
                                    String domainName,
                                    Set<DomainPermission> domainPermissions) {
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions);
   }

   @Override
   public void grantDomainPermissions(Resource accessorResource,
                                      String domainName,
                                      DomainPermission domainPermission,
                                      DomainPermission... domainPermissions) {
      accessControlContext.grantDomainPermissions(accessorResource, domainName, domainPermission, domainPermissions);
   }

   @Override
   public void revokeDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       DomainPermission domainPermission,
                                       DomainPermission... domainPermissions) {
      accessControlContext.revokeDomainPermissions(accessorResource, domainName, domainPermission, domainPermissions);
   }

   @Override
   public Set<DomainPermission> getDomainPermissions(Resource accessorResource,
                                                     String domainName) {
      return accessControlContext.getDomainPermissions(accessorResource, domainName);
   }

   @Override
   public Map<String, Set<DomainPermission>> getDomainPermissionsMap(Resource accessorResource) {
      return accessControlContext.getDomainPermissionsMap(accessorResource);
   }

   @Override
   public Set<DomainPermission> getEffectiveDomainPermissions(Resource accessorResource,
                                                              String domainName) {
      return accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
   }

   @Override
   public Map<String, Set<DomainPermission>> getEffectiveDomainPermissionsMap(Resource accessorResource) {
      return accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
   }

   @Override
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            String domainName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions) {
      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermissions);
   }

   @Override
   public void grantResourceCreatePermissions(Resource accessorResource,
                                              String resourceClassName,
                                              String domainName,
                                              ResourceCreatePermission resourceCreatePermission,
                                              ResourceCreatePermission... resourceCreatePermissions) {
      accessControlContext.grantResourceCreatePermissions(accessorResource, resourceClassName, domainName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public Set<ResourceCreatePermission> getResourceCreatePermissions(Resource accessorResource,
                                                                     String resourceClassName,
                                                                     String domainName) {
      return accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName, domainName);
   }

   @Override
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName,
                                                                              String domainName) {
      return accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
   }

   @Override
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions) {
      accessControlContext.setResourceCreatePermissions(accessorResource, resourceClassName, resourceCreatePermissions);
   }

   @Override
   public void grantResourceCreatePermissions(Resource accessorResource,
                                              String resourceClassName,
                                              ResourceCreatePermission resourceCreatePermission,
                                              ResourceCreatePermission... resourceCreatePermissions) {
      accessControlContext.grantResourceCreatePermissions(accessorResource, resourceClassName, resourceCreatePermission, resourceCreatePermissions);
   }

   @Override
   public Set<ResourceCreatePermission> getResourceCreatePermissions(Resource accessorResource,
                                                                     String resourceClassName) {
      return accessControlContext.getResourceCreatePermissions(accessorResource, resourceClassName);
   }

   @Override
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName) {
      return accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
   }

   @Override
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreatePermissionsMap(Resource accessorResource) {
      return accessControlContext.getResourceCreatePermissionsMap(accessorResource);
   }

   @Override
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getEffectiveResourceCreatePermissionsMap(Resource accessorResource) {
      return accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource);
   }

   @Override
   public void setResourcePermissions(Resource accessorResource,
                                      Resource accessedResource,
                                      Set<ResourcePermission> resourcePermissions) {
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);
   }

   @Override
   public void grantResourcePermissions(Resource accessorResource,
                                        Resource accessedResource,
                                        ResourcePermission resourcePermission,
                                        ResourcePermission... resourcePermissions) {
      accessControlContext.grantResourcePermissions(accessorResource, accessedResource, resourcePermission, resourcePermissions);
   }

   @Override
   public void revokeResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         ResourcePermission resourcePermission,
                                         ResourcePermission... resourcePermissions) {
      accessControlContext.revokeResourcePermissions(accessorResource, accessedResource, resourcePermission, resourcePermissions);
   }

   @Override
   public Set<ResourcePermission> getResourcePermissions(Resource accessorResource,
                                                         Resource accessedResource) {
      return accessControlContext.getResourcePermissions(accessorResource, accessedResource);
   }

   @Override
   public Set<ResourcePermission> getEffectiveResourcePermissions(Resource accessorResource,
                                                                  Resource accessedResource) {
      return accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
   }

   @Override
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            String domainName,
                                            Set<ResourcePermission> resourcePermissions) {
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, resourcePermissions);
   }

   @Override
   public void grantGlobalResourcePermissions(Resource accessorResource,
                                              String resourceClassName,
                                              String domainName,
                                              ResourcePermission resourcePermission,
                                              ResourcePermission... resourcePermissions) {
      accessControlContext.grantGlobalResourcePermissions(accessorResource, resourceClassName, domainName, resourcePermission, resourcePermissions);
   }

   @Override
   public void revokeGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourcePermission,
                                                           resourcePermissions);
   }

   @Override
   public Set<ResourcePermission> getGlobalResourcePermissions(Resource accessorResource,
                                                               String resourceClassName,
                                                               String domainName) {
      return accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
   }

   @Override
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName,
                                                                        String domainName) {
      return accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
   }

   @Override
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions) {
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, resourcePermissions);
   }

   @Override
   public void grantGlobalResourcePermissions(Resource accessorResource,
                                              String resourceClassName,
                                              ResourcePermission resourcePermission,
                                              ResourcePermission... resourcePermissions) {
      accessControlContext.grantGlobalResourcePermissions(accessorResource, resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public void revokeGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      accessControlContext.revokeGlobalResourcePermissions(accessorResource, resourceClassName, resourcePermission, resourcePermissions);
   }

   @Override
   public Set<ResourcePermission> getGlobalResourcePermissions(Resource accessorResource,
                                                               String resourceClassName) {
      return accessControlContext.getGlobalResourcePermissions(accessorResource, resourceClassName);
   }

   @Override
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName) {
      return accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
   }

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalResourcePermissionsMap(Resource accessorResource) {
      return accessControlContext.getGlobalResourcePermissionsMap(accessorResource);
   }

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getEffectiveGlobalResourcePermissionsMap(Resource accessorResource) {
      return accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
   }

   @Override
   public List<String> getResourceClassNames() {
      return accessControlContext.getResourceClassNames();
   }

   @Override
   public List<String> getResourcePermissionNames(String resourceClassName) {
      return accessControlContext.getResourcePermissionNames(resourceClassName);
   }
}
