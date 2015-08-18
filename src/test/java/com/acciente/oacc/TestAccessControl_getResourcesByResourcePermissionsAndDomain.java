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

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName));
      assertThat(resourcesByAccessorAndPermissionAndDomain.isEmpty(), is(true));

      // test set-based versions
      Set<Resource> resourcesByAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName)));
      assertThat(resourcesByAccessorAndPermissionAndDomain2.isEmpty(), is(true));
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

      // set permission between accessor and accessed
      Set<ResourcePermission> resourcePermissions1 = setOf(ResourcePermissions.getInstance(permissionName1));
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions1);
      accessControlContext.setResourcePermissions(accessorResource, accessedSysDomainResource, resourcePermissions1);

      // verify
      Set<Resource> expectedResources = setOf(accessedResource);

      Set<Resource> resourcesByAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              ResourcePermissions
                                                                                    .getInstance(permissionName1));
      assertThat(resourcesByAccessorAndPermissionAndDomain, is(expectedResources));

      Set<Resource> resourcesByAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(permissionName1)));
      assertThat(resourcesByAccessorAndPermissionAndDomain2, is(expectedResources));
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

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain2, is(expectedResources_queriedDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_partialDirect() {
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
      final Resource resource1_queriedClassAccessorDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource2_queriedClassAccessorDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);
      final Resource resource_unqueriedClassAccessorDomain
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
                                                  resource1_queriedClassAccessorDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1),
                                                        ResourcePermissions.getInstance(queriedPermission2)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_queriedClassAccessorDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassAccessorDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_queriedDomain = setOf(resource1_queriedClassQueriedDomain);
      final Set<Resource> expectedResources_accessorDomain = setOf(resource1_queriedClassAccessorDomain);

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
      assertThat(resourcesByAccessorAndPermissionAndAccessorDomain, is(expectedResources_accessorDomain));

      Set<Resource> resourcesByAccessorAndPermissionAndAccessorDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission2),
                                                                                    ResourcePermissions
                                                                                          .getInstance(queriedPermission1)));
      assertThat(resourcesByAccessorAndPermissionAndAccessorDomain2, is(expectedResources_accessorDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermissionAndDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2));
      assertThat(resourcesByAuthenticatedAccessorAndPermissionAndDomain, is(expectedResources_queriedDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain1
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission1));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain1,
                 is(setOf(resource1_queriedClassQueriedDomain, resource2_queriedClassQueriedDomain)));

      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain2
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission2));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain2, is(expectedResources_queriedDomain));

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

      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain3
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission1)));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain3,
                 is(setOf(resource1_queriedClassQueriedDomain, resource2_queriedClassQueriedDomain)));

      Set<Resource> resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain4
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                queriedPermission2)));
      assertThat(resourcesByAuthenticatedAccessorAndSinglePermissionAndDomain4, is(expectedResources_queriedDomain));
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource= generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final String implicitDomain = accessControlContext.getDomainNameByResource(authenticatableResource);
      final Resource resource_queriedClassImplicitDomain
            = accessControlContext.createResource(queriedResourceClass, implicitDomain);
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

      // set non-query permissions authenticatable has on accessor
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.DELETE),
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                        ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS)));

      // authenticate without query authorization
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
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
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
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_withImplicitQueryAuthorization_shouldSucceedAsAuthorized() {
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

      // set permission: authenticatable --IMPERSONATE--> accessor
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate with implicit query authorization
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

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
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_withQueryAuthorization_shouldSucceedAsAuthorized() {
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
                                                  setOf(ResourcePermissions.getInstance(
                                                        unqueriedResourceClassPermissionName)));

      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);

      // authenticate with query authorization
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

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
      final Resource resource1_accessorDomain = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource2_queriedDomain = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource2_accessorDomain = accessControlContext.createResource(queriedResourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource1_queriedDomain,
                                                  setOf(permission1_withoutGrant, permission2_withGrant));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_queriedDomain,
                                                  setOf(permission1_withGrant, permission2_withoutGrant));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource1_accessorDomain,
                                                  setOf(permission1_withoutGrant, permission2_withGrant));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_accessorDomain,
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

      final Set<Resource> expected_p1_withoutGrant_accessorDomain = setOf(resource1_accessorDomain,
                                                                          resource2_accessorDomain);
      final Set<Resource> expected_p1_withGrant_accessorDomain = setOf(resource2_accessorDomain);

      Set<Resource> forSession_by_p1_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withoutGrant);
      assertThat(forSession_by_p1_queriedDomain, is(expected_p1_withoutGrant_queriedDomain));
      forSession_by_p1_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withoutGrant));
      assertThat(forSession_by_p1_queriedDomain, is(expected_p1_withoutGrant_queriedDomain));

      Set<Resource> forSession_by_p1_accessorDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              permission1_withoutGrant);
      assertThat(forSession_by_p1_accessorDomain, is(expected_p1_withoutGrant_accessorDomain));
      forSession_by_p1_accessorDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              setOf(permission1_withoutGrant));
      assertThat(forSession_by_p1_accessorDomain, is(expected_p1_withoutGrant_accessorDomain));

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

      Set<Resource> forSelf_by_p1wG_accessorDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              permission1_withGrant);
      assertThat(forSelf_by_p1wG_accessorDomain, is(expected_p1_withGrant_accessorDomain));
      forSelf_by_p1wG_accessorDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              setOf(permission1_withGrant));
      assertThat(forSelf_by_p1wG_accessorDomain, is(expected_p1_withGrant_accessorDomain));

      Set<Resource> forSession_by_p1_p2wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              permission1_withoutGrant,
                                                                              permission2_withGrant);
      assertThat(forSession_by_p1_p2wG_queriedDomain, is(setOf(resource1_queriedDomain)));
      forSession_by_p1_p2wG_queriedDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              queriedDomain,
                                                                              setOf(permission1_withoutGrant,
                                                                                    permission2_withGrant));
      assertThat(forSession_by_p1_p2wG_queriedDomain, is(setOf(resource1_queriedDomain)));

      Set<Resource> forSession_by_p1_p2wG_accessorDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              permission1_withoutGrant,
                                                                              permission2_withGrant);
      assertThat(forSession_by_p1_p2wG_accessorDomain, is(setOf(resource1_accessorDomain)));
      forSession_by_p1_p2wG_accessorDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              accessorDomain,
                                                                              setOf(permission1_withoutGrant,
                                                                                    permission2_withGrant));
      assertThat(forSession_by_p1_p2wG_accessorDomain, is(setOf(resource1_accessorDomain)));
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
      final Resource resource_queriedClassAccessorDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource_unqueriedPermission
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);
      final Resource resource_unqueriedClassAccessorDomain
            = accessControlContext.createResource(unqueriedResourceClass, accessorDomain);

      // set permission between donor and accessed resources
      Set<ResourcePermission> queriedResourcePermissions
            = setOf(ResourcePermissions.getInstance(queriedPermission));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_queriedClassQueriedDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_queriedClassAccessorDomain,
                                                  queriedResourcePermissions);
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));
      accessControlContext.setResourcePermissions(donorResource,
                                                  resource_unqueriedClassAccessorDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // set accessor --INHERIT--> donor
      Set<ResourcePermission> inheritPermission = new HashSet<>();
      inheritPermission.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritPermission);

      // verify as system resource
      final Set<Resource> expectedResources_queriedDomain = setOf(resource_queriedClassQueriedDomain);

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

      final String unqueriedResourceClass = generateResourceClass(false, false);
      final String unqueriedResourceClassPermissionName = generateResourceClassPermission(unqueriedResourceClass);
      final Resource resource_unqueriedClassQueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, queriedDomain);
      final Resource resource_unqueriedClassAccessorDomain
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
   }

   @Test
   public void getResourcesByResourcePermissionsAndDomain_domainInherited_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain1 = generateChildDomain(parentDomain);
      final String grandChildDomain1 = generateChildDomain(childDomain1);
      final String childDomain2 = generateChildDomain(parentDomain);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermissionName = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_parentDomain = accessControlContext.createResource(queriedResourceClass, parentDomain);
      final Resource resource_grandChildDomain1 = accessControlContext.createResource(queriedResourceClass, grandChildDomain1);
      final Resource resource_childDomain2 = accessControlContext.createResource(queriedResourceClass, childDomain2);

      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessorChildDomain1 = generateChildDomain(accessorDomain);
      final String accessorGrandChildDomain1 = generateChildDomain(accessorChildDomain1);
      final String accessorChildDomain2 = generateChildDomain(accessorDomain);
      final Resource resource_accessorDomain = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource_accessorGrandChildDomain1 = accessControlContext.createResource(queriedResourceClass, accessorGrandChildDomain1);
      final Resource resource_accessorChildDomain2 = accessControlContext.createResource(queriedResourceClass, accessorChildDomain2);
      final String unqueriedDomain = generateDomain();
      final String unqueriedResourceClass = generateResourceClass(false, false);
      accessControlContext.createResourcePermission(unqueriedResourceClass, unqueriedPermissionName);
      final Resource resource_unqueriedClassGrandChildDomain1
            = accessControlContext.createResource(unqueriedResourceClass, grandChildDomain1);
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
                                                        grandChildDomain1,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        accessorDomain,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        accessorChildDomain2,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        accessorGrandChildDomain1,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_parentDomain = setOf(resource_parentDomain,
                                                                 resource_grandChildDomain1,
                                                                 resource_childDomain2);
      final Set<Resource> expectedResources_childDomain1 = setOf(resource_grandChildDomain1);


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

      Set<Resource> resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

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
   public void getResourcesByResourcePermissionsAndDomain_domainInherited_systemPermission_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain1 = generateChildDomain(parentDomain);
      final String grandChildDomain1 = generateChildDomain(childDomain1);
      final String childDomain2 = generateChildDomain(parentDomain);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = ResourcePermissions.QUERY;
      final String unqueriedPermissionName = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_parentDomain = accessControlContext.createResource(queriedResourceClass, parentDomain);
      final Resource resource_grandChildDomain1 = accessControlContext.createResource(queriedResourceClass, grandChildDomain1);
      final Resource resource_childDomain2 = accessControlContext.createResource(queriedResourceClass, childDomain2);

      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessorChildDomain1 = generateChildDomain(accessorDomain);
      final String accessorGrandChildDomain1 = generateChildDomain(accessorChildDomain1);
      final String accessorChildDomain2 = generateChildDomain(accessorDomain);
      final Resource resource_accessorDomain = accessControlContext.createResource(queriedResourceClass, accessorDomain);
      final Resource resource_accessorGrandChildDomain1 = accessControlContext.createResource(queriedResourceClass, accessorGrandChildDomain1);
      final Resource resource_accessorChildDomain2 = accessControlContext.createResource(queriedResourceClass, accessorChildDomain2);
      final String unqueriedDomain = generateDomain();
      final String unqueriedResourceClass = generateResourceClass(false, false);
      accessControlContext.createResourcePermission(unqueriedResourceClass, unqueriedPermissionName);
      final Resource resource_unqueriedClassGrandChildDomain1
            = accessControlContext.createResource(unqueriedResourceClass, grandChildDomain1);
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
                                                        grandChildDomain1,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        accessorDomain,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        accessorChildDomain2,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        accessorGrandChildDomain1,
                                                        setOf(ResourcePermissions.getInstance(unqueriedPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_parentDomain = setOf(resource_parentDomain,
                                                                 resource_grandChildDomain1,
                                                                 resource_childDomain2);
      final Set<Resource> expectedResources_childDomain1 = setOf(resource_grandChildDomain1);


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

      Set<Resource> resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

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
      final String otherDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(true, false);
      final String queriedPermission = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermissionName = generateResourceClassPermission(queriedResourceClass);
      final Resource resource_parentDomain
            = accessControlContext.createResource(queriedResourceClass, parentDomain, PasswordCredentials.newInstance(generateUniquePassword()));
      final Resource resource_childDomain
            = accessControlContext.createResource(queriedResourceClass, childDomain, PasswordCredentials.newInstance(generateUniquePassword()));
      final Resource resource_otherDomain
            = accessControlContext.createResource(queriedResourceClass, otherDomain, PasswordCredentials.newInstance(generateUniquePassword()));

      final String accessorDomain = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessorChildDomain = generateChildDomain(accessorDomain);
      final Resource resource_accessorDomain
            = accessControlContext.createResource(queriedResourceClass, accessorDomain, PasswordCredentials.newInstance(generateUniquePassword()));
      final Resource resource_accessorChildDomain
            = accessControlContext.createResource(queriedResourceClass, accessorChildDomain, PasswordCredentials.newInstance(generateUniquePassword()));
      final String unqueriedDomain = generateDomain();
      final String unqueriedResourceClass = generateResourceClass(false, false);
      accessControlContext.createResourcePermission(unqueriedResourceClass, unqueriedPermissionName);
      final Resource resource_unqueriedClassChildDomain
            = accessControlContext.createResource(unqueriedResourceClass, childDomain);
      final Resource resource_unqueriedClassAccessorChildDomain
            = accessControlContext.createResource(unqueriedResourceClass, accessorChildDomain);
      final Resource resource_unqueriedClassUnqueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, unqueriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, unqueriedDomain, PasswordCredentials.newInstance(generateUniquePassword()));

      // set super-user permission for accessor
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.setDomainPermissions(accessorResource,
                                                accessorDomain,
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

      Set<Resource> resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      resourcesByPermissionAndParentDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              parentDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndParentDomain, is(expectedResources_parentDomain));

      Set<Resource> resourcesByPermissionAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByPermissionAndChildDomain, is(expectedResources_childDomain));

      resourcesByPermissionAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByPermissionAndChildDomain, is(expectedResources_childDomain));

      Set<Resource> resourcesByMultiplePermissionsAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain,
                                                                              ResourcePermissions
                                                                                    .getInstance(ResourcePermissions.IMPERSONATE),
                                                                              ResourcePermissions
                                                                                    .getInstance(queriedPermission));
      assertThat(resourcesByMultiplePermissionsAndChildDomain, is(expectedResources_childDomain));

      resourcesByMultiplePermissionsAndChildDomain
            = accessControlContext.getResourcesByResourcePermissionsAndDomain(accessorResource,
                                                                              queriedResourceClass,
                                                                              childDomain,
                                                                              setOf(ResourcePermissions
                                                                                          .getInstance(
                                                                                                ResourcePermissions.IMPERSONATE),
                                                                                    ResourcePermissions
                                                                                          .getInstance(queriedPermission)));
      assertThat(resourcesByMultiplePermissionsAndChildDomain, is(expectedResources_childDomain));


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
      final Resource resource_accessorDomain = accessControlContext.createResource(resourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_accessorDomain,
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
      final Resource resource_accessorDomain = accessControlContext.createResource(resourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_accessorDomain,
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
      final Resource resource_accessorDomain = accessControlContext.createResource(resourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_accessorDomain,
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
      final Resource resource_accessorDomain = accessControlContext.createResource(resourceClass, accessorDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission, true)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_accessorDomain,
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
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(nonExistentResource).toLowerCase() + " not found"));
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
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(nonExistentResource).toLowerCase() + " not found"));
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
   }
}
