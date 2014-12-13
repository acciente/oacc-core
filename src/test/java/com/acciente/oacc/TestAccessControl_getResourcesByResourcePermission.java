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

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestAccessControl_getResourcesByResourcePermission extends TestAccessControlBase {
   @Test
   public void getResourcesByResourcePermission_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByPermission.isEmpty(), is(true));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName),
                                                                    domainName);
      assertThat(resourcesByPermissionAndDomain.isEmpty(), is(true));

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByAccessorAndPermission.isEmpty(), is(true));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName),
                                                                    domainName);
      assertThat(resourcesByAccessorAndPermissionAndDomain.isEmpty(), is(true));
   }

   @Test
   public void getResourcesByResourcePermission_direct_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, domainName);

      // set permission between sysresource and accessed
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermissions.getInstance(permissionName));
      accessControlContext.setResourcePermissions(SYS_RESOURCE, accessedResource, resourcePermissions);

      // set permission between accessor and accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions);

      // verify
      Set<Resource> expectedResources = new HashSet<>();
      expectedResources.add(accessedResource);

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByPermission, is(expectedResources));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName),
                                                                    domainName);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    resourceClassName,
                                                                    ResourcePermissions.getInstance(permissionName),
                                                                    domainName);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));
   }

   @Test
   public void getResourcesByResourcePermission_direct_validAsAuthorized() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, generateDomain());
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set permission between accessor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassUnqueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));
   }

   @Test
   public void getResourcesByResourcePermission_inherited_validAsAuthorized() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, generateDomain());
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set permission between donor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_queriedClassUnqueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // set accessor --INHERIT--> donor
      Set<ResourcePermission> inheritPermission = new HashSet<>();
      inheritPermission.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritPermission);

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));
   }

   @Test
   public void getResourcesByResourcePermission_global_validAsAuthorized() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final String unqueriedDomain = generateDomain();
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, unqueriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set global permission for accessor
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)),
                                                        queriedDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)),
                                                        unqueriedDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)),
                                                        queriedDomain);

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);


      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    queriedDomain);
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));
   }

   @Test
   public void getResourcesByResourcePermission_domainInherited_validAsAuthorized() throws AccessControlException {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain1 = generateChildDomain(parentDomain);
      final String childDomain2 = generateChildDomain(parentDomain);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermissionName = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_parentDomain = accessControlContext.createResource(queriedResourceClass, parentDomain);
      final Resource resource_childDomain1 = accessControlContext.createResource(queriedResourceClass, childDomain1);
      final Resource resource_childDomain2 = accessControlContext.createResource(queriedResourceClass, childDomain2);

      final String unqueriedDomain = generateDomain();
      final String unqueriedResourceClass = generateResourceClass(false, false);
      accessControlContext.createResourcePermission(unqueriedResourceClass, unqueriedPermissionName);
      final Resource resource_unqueriedClassChildDomain1
            = accessControlContext.createResource(unqueriedResourceClass, childDomain1);
      final Resource resource_unqueriedClassUnqueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, unqueriedDomain);

      // set global permission for accessor
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)),
                                                        parentDomain);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)),
                                                        childDomain2);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)),
                                                        childDomain1);

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_parentDomain,
                                                              resource_childDomain1,
                                                              resource_childDomain2);
      final Set<Resource> expectedResources_childDomain1 = setOf(resource_childDomain1);


      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    parentDomain);
      assertThat(resourcesByAccessorAndPermissionAndParentDomain, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermission(accessorResource,
                                                                    queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    childDomain1);
      assertThat(resourcesByAccessorAndPermissionAndChildDomain1, is(expectedResources_childDomain1));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    parentDomain);
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_anyDomain));

      Set<Resource> resourcesByPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermission(queriedResourceClass,
                                                                    ResourcePermissions.getInstance(queriedPermission),
                                                                    childDomain1);
      assertThat(resourcesByPermissionAndChildDomain1, is(expectedResources_childDomain1));
   }
}
