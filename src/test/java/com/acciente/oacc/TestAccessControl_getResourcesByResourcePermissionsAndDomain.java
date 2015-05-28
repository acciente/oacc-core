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

import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getResourcesByResourcePermissionsAndDomain extends TestAccessControlBase {

   @Test
   public void getResourcesByResourcePermissionsAndDomain_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName,
                                                                              domainName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName));
      assertThat(resourcesByPermissionAndDomain.isEmpty(), is(true));
      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName));
      assertThat(resourcesByPermissionAndImplicitDomain.isEmpty(), is(true));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName));
      assertThat(resourcesByAccessorAndPermissionAndDomain.isEmpty(), is(true));
      Set<Resource> resourcesByAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain.isEmpty(), is(true));

      // test set-based versions
      Set<Resource> resourcesByPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName,
                                                                              domainName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName)));
      assertThat(resourcesByPermissionAndDomain2.isEmpty(), is(true));
      Set<Resource> resourcesByPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName)));
      assertThat(resourcesByPermissionAndImplicitDomain2.isEmpty(), is(true));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName)));
      assertThat(resourcesByAccessorAndPermissionAndDomain2.isEmpty(), is(true));
      Set<Resource> resourcesByAccessorAndPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName)));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain2.isEmpty(), is(true));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_direct_validAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName1 = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, domainName);
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final Resource accessedSysDomainResource = accessControlContext.createResource(resourceClassName, sysDomainName);

      // set permission between sysresource and accessed
      Set<ResourcePermission> resourcePermissions1 = setOf(ResourcePermissions.getInstance(permissionName1));
      accessControlContext.setResourcePermissions(SYS_RESOURCE, accessedResource, resourcePermissions1);
      accessControlContext.setResourcePermissions(SYS_RESOURCE, accessedSysDomainResource, resourcePermissions1);

      // set permission between accessor and accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions1);
      accessControlContext.setResourcePermissions(accessorResource, accessedSysDomainResource, resourcePermissions1);

      // verify
      Set<Resource> expectedResources = setOf(accessedResource);
      Set<Resource> expectedSysDomainResources = setOf(accessedSysDomainResource);

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName,
                                                                              domainName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName1));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));
      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName1));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedSysDomainResources));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName1));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));
      Set<Resource> resourcesByAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName1));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain, is(expectedSysDomainResources));

      // test set-based versions
      Set<Resource> resourcesByPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName,
                                                                              domainName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName1)));
      assertThat(resourcesByPermissionAndDomain2, is(expectedResources));
      Set<Resource> resourcesByPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClassName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName1)));
      assertThat(resourcesByPermissionAndImplicitDomain2, is(expectedSysDomainResources));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName1)));
      assertThat(resourcesByAccessorAndPermissionAndDomain2, is(expectedResources));
      Set<Resource> resourcesByAccessorAndPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName1)));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain2, is(expectedSysDomainResources));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_direct_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassAccessorDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);

      // set permission between accessor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassAccessorDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndDomain2, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));

      final Set<Resource> expectedResources_implicitDomain = setOf(resource_queriedClassAccessorDomain);
      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndDomain2, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndImplicitDomain2, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain2, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain2, is(expectedResources_implicitDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_partialDirect_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission1 = generateResourceClassPermission(queriedResourceClass);
      final String queriedPermission2 = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource1_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource2_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource1_queriedClassImplicitDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource2_queriedClassImplicitDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);
      final Resource resource_unqueriedClassImplicitDomain
            = accessControlContext.createResource(unqueriedResourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource1_queriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1),
                                                        ResourcePermissions.getInstance(queriedPermission2)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_queriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource1_queriedClassImplicitDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1),
                                                        ResourcePermissions.getInstance(queriedPermission2)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_queriedClassImplicitDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassImplicitDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_queriedDomain = setOf(resource1_queriedClassQueriedDomain);
      final Set<Resource> expectedResources_implicitDomain = setOf(resource1_queriedClassImplicitDomain);

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission2),
                                                                                    ResourcePermissions
                                                                                          .getInstance(queriedPermission1)));
      assertThat(resourcesByAccessorAndPermissionAndDomain2, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndAccessorDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1));
      assertThat(resourcesByAccessorAndPermissionAndAccessorDomain, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndAccessorDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission2),
                                                                                    ResourcePermissions
                                                                                          .getInstance(queriedPermission1)));
      assertThat(resourcesByAccessorAndPermissionAndAccessorDomain2, is(expectedResources_implicitDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain1,
                 is(setOf(resource1_queriedClassQueriedDomain, resource2_queriedClassQueriedDomain)));
      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndImplicitDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndImplicitDomain1,
                 is(setOf(resource1_queriedClassImplicitDomain, resource2_queriedClassImplicitDomain)));

      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain2, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndImplicitDomain2, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission1),
                                                                                    ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission2)));
      assertThat(resourcesByPermissionAndDomain2, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission1),
                                                                                    ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission2)));
      assertThat(resourcesByPermissionAndImplicitDomain2, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission1),
                                                                                    ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission2)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain2, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission1),
                                                                                    ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission2)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain2, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain3
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission1)));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain3,
                 is(setOf(resource1_queriedClassQueriedDomain, resource2_queriedClassQueriedDomain)));
      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndImplicitDomain3
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission1)));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndImplicitDomain3,
                 is(setOf(resource1_queriedClassImplicitDomain, resource2_queriedClassImplicitDomain)));

      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain4
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission2)));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain4, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndImplicitDomain4
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission2)));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndImplicitDomain4, is(expectedResources_implicitDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_unauthorized_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource= generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      final String queriedDomain = generateDomain();
      final String implicitDomain = accessControlContext.getDomainNameByResource(authenticatableResource);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassImplicitDomain
            = accessControlContext.createResource(queriedResourceClass, implicitDomain);
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
                                                  resource_queriedClassImplicitDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         queriedResourceClass,
                                                                         queriedDomain,
                                                                         ResourcePermissions
                                                                               .getInstance(queriedPermission));
         fail("getting resources by resource permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("retrieve resources by permission"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         queriedResourceClass,
                                                                         ResourcePermissions
                                                                               .getInstance(queriedPermission));
         fail("getting resources by resource permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("retrieve resources by permission"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         queriedResourceClass,
                                                                         queriedDomain,
                                                                         setOf(ResourcePermissions
                                                                               .getInstance(queriedPermission)));
         fail("getting resources by resource permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("retrieve resources by permission"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         queriedResourceClass,
                                                                         setOf(ResourcePermissions
                                                                               .getInstance(queriedPermission)));
         fail("getting resources by resource permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("retrieve resources by permission"));
      }
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_authorized_shouldSucceed() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource= generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

      final String queriedDomain = generateDomain();
      final String implicitDomain = accessControlContext.getDomainNameByResource(authenticatableResource);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassImplicitDomain
            = accessControlContext.createResource(queriedResourceClass, implicitDomain);
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);
      final Resource resource_unqueriedClassImplicitDomain
            = accessControlContext.createResource(unqueriedResourceClass, implicitDomain);

      // set permission between accessor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassImplicitDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassImplicitDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);
      final Set<Resource> expectedResources_implicitDomain = setOf(resource_queriedClassImplicitDomain);

      // set permission: authenticatable --IMPERSONATE--> accessor
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
      Set<Resource> resourcesByAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
      resourcesByAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      // set permission: authenticatable --INHERIT--> accessor
      authenticateSystemResource();
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
      resourcesByAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
      resourcesByAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      // set permission: authenticatable --RESET_CREDENTIALS--> accessor
      authenticateSystemResource();
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
      resourcesByAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));
      resourcesByAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_directWithAndWithoutGrant_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String permissionName1 = generateResourceClassPermission(queriedResourceClass);
      final String permissionName2 = generateResourceClassPermission(queriedResourceClass);
      final ResourcePermission permission1_withoutGrant = ResourcePermissions.getInstance(permissionName1);
      final ResourcePermission permission1_withGrant = ResourcePermissions.getInstance(permissionName1, true);
      final ResourcePermission permission2_withoutGrant = ResourcePermissions.getInstance(permissionName2);
      final ResourcePermission permission2_withGrant = ResourcePermissions.getInstance(permissionName2, true);
      final Resource resource1_queriedDomain = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource1_implicitDomain = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource2_queriedDomain = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource2_implicitDomain = accessControlContext.createResource(queriedResourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource1_queriedDomain,
                                                  setOf(permission1_withoutGrant, permission2_withGrant));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_queriedDomain,
                                                  setOf(permission1_withGrant, permission2_withoutGrant));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource1_implicitDomain,
                                                  setOf(permission1_withoutGrant, permission2_withGrant));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_implicitDomain,
                                                  setOf(permission1_withGrant, permission2_withoutGrant));

      // verify as system resource
      final Set<Resource> expected_p1_withoutGrant_queriedDomain = setOf(resource1_queriedDomain,
                                                                         resource2_queriedDomain);
      final Set<Resource> expected_p1_withGrant_queriedDomain = setOf(resource2_queriedDomain);

      Set<Resource> forAccessor_by_p1_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withoutGrant);
      assertThat(forAccessor_by_p1_queriedDomain, is(expected_p1_withoutGrant_queriedDomain));

      forAccessor_by_p1_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withoutGrant));
      assertThat(forAccessor_by_p1_queriedDomain, is(expected_p1_withoutGrant_queriedDomain));

      Set<Resource> forAccessor_by_p1wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withGrant);
      assertThat(forAccessor_by_p1wG_queriedDomain, is(expected_p1_withGrant_queriedDomain));

      forAccessor_by_p1wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withGrant));
      assertThat(forAccessor_by_p1wG_queriedDomain, is(expected_p1_withGrant_queriedDomain));

      Set<Resource> forAccessor_by_p1_p2wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withoutGrant,
                                                                              permission2_withGrant);
      assertThat(forAccessor_by_p1_p2wG_queriedDomain, is(setOf(resource1_queriedDomain)));

      forAccessor_by_p1_p2wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withoutGrant,
                                                                                    permission2_withGrant));
      assertThat(forAccessor_by_p1_p2wG_queriedDomain, is(setOf(resource1_queriedDomain)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<Resource> expected_p1_withoutGrant_implicitDomain = setOf(resource1_implicitDomain,
                                                                          resource2_implicitDomain);
      final Set<Resource> expected_p1_withGrant_implicitDomain = setOf(resource2_implicitDomain);

      Set<Resource> forSession_by_p1_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withoutGrant);
      assertThat(forSession_by_p1_queriedDomain, is(expected_p1_withoutGrant_queriedDomain));
      forSession_by_p1_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withoutGrant));
      assertThat(forSession_by_p1_queriedDomain, is(expected_p1_withoutGrant_queriedDomain));

      Set<Resource> forSession_by_p1_implicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              permission1_withoutGrant);
      assertThat(forSession_by_p1_implicitDomain, is(expected_p1_withoutGrant_implicitDomain));
      forSession_by_p1_implicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(permission1_withoutGrant));
      assertThat(forSession_by_p1_implicitDomain, is(expected_p1_withoutGrant_implicitDomain));

      Set<Resource> forSession_by_p1wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withGrant);
      assertThat(forSession_by_p1wG_queriedDomain, is(expected_p1_withGrant_queriedDomain));
      forSession_by_p1wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withGrant));
      assertThat(forSession_by_p1wG_queriedDomain, is(expected_p1_withGrant_queriedDomain));

      Set<Resource> forSession_by_p1wG_implicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              permission1_withGrant);
      assertThat(forSession_by_p1wG_implicitDomain, is(expected_p1_withGrant_implicitDomain));
      forSession_by_p1wG_implicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(permission1_withGrant));
      assertThat(forSession_by_p1wG_implicitDomain, is(expected_p1_withGrant_implicitDomain));

      Set<Resource> forSelf_by_p1wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withGrant);
      assertThat(forSelf_by_p1wG_queriedDomain, is(expected_p1_withGrant_queriedDomain));
      forSelf_by_p1wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withGrant));
      assertThat(forSelf_by_p1wG_queriedDomain, is(expected_p1_withGrant_queriedDomain));

      Set<Resource> forSelf_by_p1wG_implicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              permission1_withGrant);
      assertThat(forSelf_by_p1wG_implicitDomain, is(expected_p1_withGrant_implicitDomain));
      forSelf_by_p1wG_implicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(permission1_withGrant));
      assertThat(forSelf_by_p1wG_implicitDomain, is(expected_p1_withGrant_implicitDomain));

      Set<Resource> forSession_by_p1_p2wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withoutGrant,
                                                                              permission2_withGrant);
      assertThat(forSession_by_p1_p2wG_queriedDomain, is(setOf(resource1_queriedDomain)));
      forSession_by_p1_p2wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withoutGrant,
                                                                                    permission2_withGrant));
      assertThat(forSession_by_p1_p2wG_queriedDomain, is(setOf(resource1_queriedDomain)));

      Set<Resource> forSession_by_p1_p2wG_implicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              permission1_withoutGrant,
                                                                              permission2_withGrant);
      assertThat(forSession_by_p1_p2wG_implicitDomain, is(setOf(resource1_implicitDomain)));
      forSession_by_p1_p2wG_implicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(permission1_withoutGrant,
                                                                                    permission2_withGrant));
      assertThat(forSession_by_p1_p2wG_implicitDomain, is(setOf(resource1_implicitDomain)));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_inherited_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();

      final String queriedDomain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassImplicitDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);
      final Resource resource_unqueriedClassImplicitDomain
            = accessControlContext.createResource(unqueriedResourceClass, accessorDomain);

      // set permission between donor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_queriedClassImplicitDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedClassImplicitDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // set accessor --INHERIT--> donor
      Set<ResourcePermission> inheritPermission = new HashSet<>();
      inheritPermission.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritPermission);

      // verify as system resource
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);
      final Set<Resource> expectedResources_implicitDomain = setOf(resource_queriedClassImplicitDomain);

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));

      resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_global_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_queriedClassImplicitDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);
      final Resource resource_unqueriedClassImplicitDomain
            = accessControlContext.createResource(unqueriedResourceClass, accessorDomain);

      // set global permission for accessor
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        queriedDomain,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        accessorDomain,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        queriedDomain,
                                                        setOf(ResourcePermissions.getInstance(
                                                              unqueriedResourceClassPermissionName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        accessorDomain,
                                                        setOf(ResourcePermissions.getInstance(
                                                              unqueriedResourceClassPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);
      final Set<Resource> expectedResources_implicitDomain = setOf(resource_queriedClassImplicitDomain);


      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));

      resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndImplicitDomain, is(expectedResources_implicitDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_domainInherited_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain1 = generateChildDomain(parentDomain);
      final String childDomain2 = generateChildDomain(parentDomain);
      final String implicitParentDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String implicitChildDomain1 = generateChildDomain(implicitParentDomain);
      final String implicitChildDomain2 = generateChildDomain(implicitParentDomain);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermissionName = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_parentDomain = accessControlContext.createResource(queriedResourceClass, parentDomain);
      final Resource resource_childDomain1 = accessControlContext.createResource(queriedResourceClass, childDomain1);
      final Resource resource_childDomain2 = accessControlContext.createResource(queriedResourceClass, childDomain2);
      final Resource resource_implicitParentDomain = accessControlContext.createResource(queriedResourceClass, implicitParentDomain);
      final Resource resource_implicitChildDomain1 = accessControlContext.createResource(queriedResourceClass, implicitChildDomain1);
      final Resource resource_implicitChildDomain2 = accessControlContext.createResource(queriedResourceClass, implicitChildDomain2);

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
                                                        parentDomain,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        childDomain2,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        childDomain1,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        implicitParentDomain,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        implicitChildDomain2,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        implicitChildDomain1,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_parentDomain = setOf(resource_parentDomain,
                                                                 resource_childDomain1,
                                                                 resource_childDomain2);
      final Set<Resource> expectedResources_childDomain1 = setOf(resource_childDomain1);


      Set<Resource> resourcesByAccessorAndPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndParentDomain, is(expectedResources_parentDomain));

      resourcesByAccessorAndPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndParentDomain, is(expectedResources_parentDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain1,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndChildDomain1, is(expectedResources_childDomain1));

      resourcesByAccessorAndPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain1,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndChildDomain1, is(expectedResources_childDomain1));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<Resource> expectedResources_implicitParentDomain = setOf(resource_implicitParentDomain,
                                                                         resource_implicitChildDomain1,
                                                                         resource_implicitChildDomain2);

      Set<Resource> resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              parentDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              parentDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      Set<Resource> resourcesByPermissionAndImplicitParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndImplicitParentDomain, is(expectedResources_implicitParentDomain));

      resourcesByPermissionAndImplicitParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndImplicitParentDomain, is(expectedResources_implicitParentDomain));

      Set<Resource> resourcesByPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              childDomain1,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndChildDomain1, is(expectedResources_childDomain1));

      resourcesByPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              childDomain1,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndChildDomain1, is(expectedResources_childDomain1));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain1,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndChildDomain1, is(expectedResources_childDomain1));

      resourcesByAuthenticatedAccessorAndPermissionAndChildDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain1,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndChildDomain1, is(expectedResources_childDomain1));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_superUser_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain = generateChildDomain(parentDomain);
      final String implicitParentDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String implicitChildDomain = generateChildDomain(implicitParentDomain);
      final String otherDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(true, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermissionName = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_parentDomain
            = accessControlContext.createResource(queriedResourceClass, parentDomain, PasswordCredentials.newInstance(generateUniquePassword()));
      final Resource resource_childDomain
            = accessControlContext.createResource(queriedResourceClass, childDomain, PasswordCredentials.newInstance(generateUniquePassword()));
      final Resource resource_implicitParentDomain
            = accessControlContext.createResource(queriedResourceClass, implicitParentDomain, PasswordCredentials.newInstance(generateUniquePassword()));
      final Resource resource_implicitChildDomain
            = accessControlContext.createResource(queriedResourceClass, implicitChildDomain, PasswordCredentials.newInstance(generateUniquePassword()));
      final Resource resource_otherDomain
            = accessControlContext.createResource(queriedResourceClass, otherDomain, PasswordCredentials.newInstance(generateUniquePassword()));

      final String unqueriedDomain = generateDomain();
      final String unqueriedResourceClass = generateResourceClass(false, false);
      accessControlContext.createResourcePermission(unqueriedResourceClass, unqueriedPermissionName);
      final Resource resource_unqueriedClassChildDomain
            = accessControlContext.createResource(unqueriedResourceClass, childDomain);
      final Resource resource_unqueriedClassImplicitChildDomain
            = accessControlContext.createResource(unqueriedResourceClass, implicitChildDomain);
      final Resource resource_unqueriedClassUnqueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, unqueriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, unqueriedDomain, PasswordCredentials.newInstance(generateUniquePassword()));

      // set super-user permission for accessor
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.setDomainPermissions(accessorResource,
                                                implicitParentDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.setDomainPermissions(accessorResource,
                                                otherDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // verify as system resource
      final Set<Resource> expectedResources_parentDomain = setOf(resource_parentDomain,
                                                                 resource_childDomain);
      final Set<Resource> expectedResources_childDomain = setOf(resource_childDomain);
      final Set<Resource> expectedResources_otherDomain = setOf(resource_otherDomain);


      Set<Resource> resourcesByAccessorAndPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndParentDomain, is(expectedResources_parentDomain));

      resourcesByAccessorAndPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndParentDomain, is(expectedResources_parentDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndChildDomain, is(expectedResources_childDomain));

      resourcesByAccessorAndPermissionAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndChildDomain, is(expectedResources_childDomain));

      Set<Resource> resourcesByAccessorAndMultiplePermissionsAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(ResourcePermissions.IMPERSONATE),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndMultiplePermissionsAndChildDomain, is(expectedResources_childDomain));

      resourcesByAccessorAndMultiplePermissionsAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                ResourcePermissions.IMPERSONATE),
                                                                                    ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndMultiplePermissionsAndChildDomain, is(expectedResources_childDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              otherDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermissionAndOtherDomain, is(expectedResources_otherDomain));

      resourcesByAccessorAndPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              otherDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermissionAndOtherDomain, is(expectedResources_otherDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<Resource> expectedResources_implicitParentDomain = setOf(resource_implicitParentDomain,
                                                                         resource_implicitChildDomain);

      Set<Resource> resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              parentDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              parentDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      Set<Resource> resourcesByPermissionAndImplicitParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndImplicitParentDomain, is(expectedResources_implicitParentDomain));

      resourcesByPermissionAndImplicitParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndImplicitParentDomain, is(expectedResources_implicitParentDomain));

      Set<Resource> resourcesByPermissionAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              childDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndChildDomain, is(expectedResources_childDomain));

      resourcesByPermissionAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              childDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndChildDomain, is(expectedResources_childDomain));

      Set<Resource> resourcesByMultiplePermissionsAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              childDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(ResourcePermissions.IMPERSONATE),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByMultiplePermissionsAndChildDomain, is(expectedResources_childDomain));

      resourcesByMultiplePermissionsAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              childDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                ResourcePermissions.IMPERSONATE),
                                                                                    ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByMultiplePermissionsAndChildDomain, is(expectedResources_childDomain));

      Set<Resource> resourcesByPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              otherDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndOtherDomain, is(expectedResources_otherDomain));

      resourcesByPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(queriedResourceClass,
                                                                              otherDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndOtherDomain, is(expectedResources_otherDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              otherDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndOtherDomain, is(expectedResources_otherDomain));

      resourcesByAuthenticatedAccessorAndPermissionAndOtherDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              otherDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndOtherDomain, is(expectedResources_otherDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_whitespaceConsistent() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);
      final Resource resource_implicitDomain = accessControlContext.createResource(resourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_implicitDomain,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      final String resourceClass_whitespaced = " " + resourceClass + "\t";
      final String permission_whitespaced = " " + permission + "\t";
      final String domain_whitespaced = " " + domain + "\t";

      // verify as system resource
      final Set<Resource> expectedResources = setOf(resource);

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClass_whitespaced,
                                                                              domain_whitespaced,
                                                                              ResourcePermissions
                                                                                    .getInstance(permission_whitespaced));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClass_whitespaced,
                                                                              domain_whitespaced,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                permission_whitespaced)));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<Resource> expectedResources_implicitDomain = setOf(resource_implicitDomain);

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass_whitespaced,
                                                                              domain_whitespaced,
                                                                              ResourcePermissions
                                                                                    .getInstance(permission_whitespaced));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));

      resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass_whitespaced,
                                                                              domain_whitespaced,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                permission_whitespaced)));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));

      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass_whitespaced,
                                                                              ResourcePermissions
                                                                                    .getInstance(permission_whitespaced));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass_whitespaced,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                permission_whitespaced)));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_nulls_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final ResourcePermission resourcePermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));
      final ResourcePermission resourcePermission2
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(null,
                                                                         resourceClass,
                                                                         domain,
                                                                         resourcePermission);
         fail("getting resources by resource permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         null,
                                                                         domain,
                                                                         resourcePermission);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         (String) null,
                                                                         resourcePermission);
         fail("getting resources by resource permission with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         (ResourcePermission) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         null);
         fail("getting resources by resource permission with null resource permission sequence should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         new ResourcePermission[]{null});
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         resourcePermission2,
                                                                         null);
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(null,
                                                                         resourceClass,
                                                                         domain,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         null,
                                                                         domain,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         (String) null,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         (Set<ResourcePermission>) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         setOf(resourcePermission,
                                                                               null));
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain((String) null, domain, resourcePermission);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         (String) null,
                                                                         resourcePermission);
         fail("getting resources by resource permission with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, domain, (ResourcePermission) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         null);
         fail("getting resources by resource permission with null resource permission sequence should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         new ResourcePermission[]{null});
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         resourcePermission2,
                                                                         null);
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain((String) null, domain, setOf(resourcePermission));
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         (String) null,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, domain, (Set<ResourcePermission>) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         setOf(resourcePermission,
                                                                               null));
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }

      // test with implicit domain
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain((Resource) null,
                                                                         resourceClass,
                                                                         resourcePermission);
         fail("getting resources by resource permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         null,
                                                                         resourcePermission);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         (ResourcePermission) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         resourcePermission,
                                                                         null);
         fail("getting resources by resource permission with null resource permission sequence should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         resourcePermission,
                                                                         new ResourcePermission[]{null});
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         resourcePermission,
                                                                         resourcePermission2,
                                                                         null);
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain((Resource) null,
                                                                         resourceClass,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         null,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         (Set<ResourcePermission>) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         setOf(resourcePermission,
                                                                               null));
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain((String) null, resourcePermission);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, (ResourcePermission) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         resourcePermission,
                                                                         null);
         fail("getting resources by resource permission with null resource permission sequence should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         resourcePermission,
                                                                         new ResourcePermission[]{null});
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         resourcePermission,
                                                                         resourcePermission2,
                                                                         null);
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain((String) null, setOf(resourcePermission));
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, (Set<ResourcePermission>) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         setOf(resourcePermission,
                                                                               null));
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         Collections.<ResourcePermission>emptySet());
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         Collections.<ResourcePermission>emptySet());
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, domain, Collections.<ResourcePermission>emptySet());
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, Collections.<ResourcePermission>emptySet());
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);
      final Resource resource_implicitDomain = accessControlContext.createResource(resourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_implicitDomain,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      // verify
      final Set<Resource> expectedResources = setOf(resource);

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClass,
                                                                              domain,
                                                                              ResourcePermissions.getInstance(permission));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClass,
                                                                              domain,
                                                                              ResourcePermissions.getInstance(permission),
                                                                              new ResourcePermission[]{});
      assertThat(resourcesByAccessorAndPermissionAndDomain2, is(expectedResources));

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<Resource> expectedResources_implicitDomain = setOf(resource_implicitDomain);

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                              domain,
                                                                              ResourcePermissions
                                                                                    .getInstance(permission));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));

      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(permission));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      Set<Resource> resourcesByPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                              domain,
                                                                              ResourcePermissions.getInstance(permission),
                                                                              new ResourcePermission[]{});
      assertThat(resourcesByPermissionAndDomain2, is(expectedResources));

      Set<Resource> resourcesByPermissionAndImplicitDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                              ResourcePermissions.getInstance(permission),
                                                                              new ResourcePermission[]{});
      assertThat(resourcesByPermissionAndImplicitDomain2, is(expectedResources_implicitDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_duplicates_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);
      final Resource resource_implicitDomain = accessControlContext.createResource(resourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_implicitDomain,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      // verify as system resource
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         ResourcePermissions
                                                                               .getInstance(permission),
                                                                         ResourcePermissions
                                                                               .getInstance(permission));
         fail("getting resources by resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         ResourcePermissions
                                                                               .getInstance(permission),
                                                                         ResourcePermissions
                                                                               .getInstance(permission));
         fail("getting resources by resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         ResourcePermissions
                                                                               .getInstance(permission),
                                                                         ResourcePermissions
                                                                               .getInstance(permission));
         fail("getting resources by resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_duplicates_shouldSucceed() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);
      final Resource resource_implicitDomain = accessControlContext.createResource(resourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission, true)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_implicitDomain,
                                                  setOf(ResourcePermissions.getInstance(permission, true)));

      // verify as system resource
      final Set<Resource> expectedResources = setOf(resource);

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClass,
                                                                              domain,
                                                                              ResourcePermissions
                                                                                    .getInstance(permission),
                                                                              ResourcePermissions
                                                                                    .getInstance(permission, true));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));

      resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClass,
                                                                              domain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permission),
                                                                                    ResourcePermissions
                                                                                          .getInstance(permission,
                                                                                                       true)));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      final Set<Resource> expectedResources_implicitDomain = setOf(resource_implicitDomain);

      Set<Resource> resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                              domain,
                                                                              ResourcePermissions
                                                                                    .getInstance(permission),
                                                                              ResourcePermissions
                                                                                    .getInstance(permission, true));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));

      resourcesByPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                              domain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permission),
                                                                                    ResourcePermissions
                                                                                          .getInstance(permission,
                                                                                                       true)));
      assertThat(resourcesByPermissionAndDomain, is(expectedResources));

      Set<Resource> resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                              ResourcePermissions
                                                                                    .getInstance(permission),
                                                                              ResourcePermissions
                                                                                    .getInstance(permission, true));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));

      resourcesByPermissionAndImplicitDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permission),
                                                                                    ResourcePermissions
                                                                                          .getInstance(permission,
                                                                                                       true)));
      assertThat(resourcesByPermissionAndImplicitDomain, is(expectedResources_implicitDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource nonExistentResource = Resources.getInstance(-999L);
      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final ResourcePermission resourcePermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));
      final ResourcePermission nonExistentPermission = ResourcePermissions.getInstance("does_not_exist");

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(nonExistentResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         resourcePermission);
         fail("getting resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine domain for resource"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         "does_not_exit",
                                                                         domain,
                                                                         resourcePermission);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         "does_not_exist",
                                                                         resourcePermission);
         fail("getting resources by resource permission with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(nonExistentResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine domain for resource"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         "does_not_exit",
                                                                         domain,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         "does_not_exist",
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         setOf(nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         domain,
                                                                         setOf(resourcePermission,
                                                                               nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain("does_not_exit", domain, resourcePermission);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         "does_not_exist",
                                                                         resourcePermission);
         fail("getting resources by resource permission with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, domain, nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain("does_not_exit", domain, setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         "does_not_exist",
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, domain, setOf(nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         setOf(resourcePermission,
                                                                               nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      // test with implicit domain
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(nonExistentResource,
                                                                         resourceClass,
                                                                         resourcePermission);
         fail("getting resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine domain for resource"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         "does_not_exit",
                                                                         resourcePermission);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         resourcePermission,
                                                                         nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(nonExistentResource,
                                                                         resourceClass,
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not determine domain for resource"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         "does_not_exit",
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         setOf(nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                         resourceClass,
                                                                         setOf(resourcePermission,
                                                                               nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      // authenticate as accessor
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain("does_not_exit", domain, resourcePermission);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         "does_not_exist",
                                                                         resourcePermission);
         fail("getting resources by resource permission with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, domain, nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         resourcePermission,
                                                                         nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain("does_not_exit", domain, setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         "does_not_exist",
                                                                         setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, domain, setOf(nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         domain,
                                                                         setOf(resourcePermission,
                                                                               nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      // test with implicit domain (and implicit accessor)
      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain("does_not_exit", resourcePermission);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         resourcePermission,
                                                                         nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain("does_not_exit", setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass, setOf(nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissionsAndDomain(resourceClass,
                                                                         setOf(resourcePermission,
                                                                               nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
