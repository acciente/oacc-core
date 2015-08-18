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

public class TestAccessControl_getResourcesByResourcePermissions extends TestAccessControlBase {
   @Test
   public void getResourcesByResourcePermissions_emptyAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName = generateResourceClassPermission(resourceClassName);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClassName,
                                                                     ResourcePermissions.getInstance(permissionName));
      assertThat(resourcesByAccessorAndPermission.isEmpty(), is(true));

      // test set-based versions
      Set<Resource> resourcesByAccessorAndPermission2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClassName,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(permissionName)));
      assertThat(resourcesByAccessorAndPermission2.isEmpty(), is(true));
   }

   @Test
   public void getResourcesByResourcePermissions_direct_validAsSystemResource() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String permissionName1 = generateResourceClassPermission(resourceClassName);
      final String domainName = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, domainName);

      // set permission between sysresource and accessed
      Set<ResourcePermission> resourcePermissions1 = setOf(ResourcePermissions.getInstance(permissionName1));
      accessControlContext.setResourcePermissions(SYS_RESOURCE, accessedResource, resourcePermissions1);

      // set permission between accessor and accessed
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, resourcePermissions1);

      // verify
      Set<Resource> expectedResources = setOf(accessedResource);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClassName,
                                                                     ResourcePermissions.getInstance(permissionName1));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));

      // test set-based versions
      Set<Resource> resourcesByAccessorAndPermission2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClassName,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(permissionName1)));
      assertThat(resourcesByAccessorAndPermission2, is(expectedResources));
   }

   @Test
   public void getResourcesByResourcePermissions_direct_validAsAuthenticated() {
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
      Set<ResourcePermission> queriedResourcePermissions = setOf(ResourcePermissions.getInstance(queriedPermission));
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

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermission2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermission2, is(expectedResources_anyDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAuthenticatedAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermission2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByAuthenticatedAccessorAndPermission2, is(expectedResources_anyDomain));
   }

   @Test
   public void getResourcesByResourcePermissions_partialDirect() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission1 = generateResourceClassPermission(queriedResourceClass);
      final String queriedPermission2 = generateResourceClassPermission(queriedResourceClass);
      final String unqueriedPermission = generateResourceClassPermission(queriedResourceClass);
      final Resource resource1_queriedClassQueriedDomain
            = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource2_queriedClassQueriedDomain
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
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource1_queriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1),
                                                        ResourcePermissions.getInstance(queriedPermission2)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_queriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_queriedClassUnqueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(queriedPermission1),
                                                        ResourcePermissions.getInstance(queriedPermission2)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedPermission,
                                                  setOf(ResourcePermissions.getInstance(unqueriedPermission)));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedClassQueriedDomain,
                                                  setOf(ResourcePermissions.getInstance(unqueriedResourceClassPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource1_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions
                                                                           .getInstance(queriedPermission2),
                                                                     ResourcePermissions
                                                                           .getInstance(queriedPermission1));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAccessorAndPermission2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission2),
                                                                           ResourcePermissions
                                                                                 .getInstance(queriedPermission1)));
      assertThat(resourcesByAccessorAndPermission2, is(expectedResources_anyDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission1),
                                                                     ResourcePermissions.getInstance(queriedPermission2));
      assertThat(resourcesByAuthenticatedAccessorAndPermission, is(expectedResources_anyDomain));

      Set<Resource> resourcesByAuthenticatedAccessorAndPermission2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission1),
                                                                           ResourcePermissions
                                                                                 .getInstance(queriedPermission2)));
      assertThat(resourcesByAuthenticatedAccessorAndPermission2, is(expectedResources_anyDomain));
   }

   @Test
   public void getResourcesByResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

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

      // set non-query permissions authenticatable has on accessor
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.DELETE),
                                                        ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                        ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS)));

      // authenticate without query authorization
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                queriedResourceClass,
                                                                ResourcePermissions.getInstance(queriedPermission));
         fail("getting resources by resource permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                queriedResourceClass,
                                                                setOf(ResourcePermissions
                                                                            .getInstance(queriedPermission)));
         fail("getting resources by resource permission without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void getResourcesByResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource= generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

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

      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);

      // set permission: authenticatable --IMPERSONATE--> accessor
      accessControlContext.setResourcePermissions(authenticatableResource,
                                                  accessorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));
   }

   @Test
   public void getResourcesByResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource= generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());

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

      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);

      // authenticate with query authorization
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

   }

   @Test
   public void getResourcesByResourcePermissions_directWithAndWithoutGrant_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String queriedDomain = generateDomain();
      final String queriedResourceClass = generateResourceClass(false, false);
      final String permissionName1 = generateResourceClassPermission(queriedResourceClass);
      final String permissionName2 = generateResourceClassPermission(queriedResourceClass);
      final ResourcePermission permission1_withoutGrant = ResourcePermissions.getInstance(permissionName1);
      final ResourcePermission permission1_withGrant = ResourcePermissions.getInstance(permissionName1, true);
      final ResourcePermission permission2_withoutGrant = ResourcePermissions.getInstance(permissionName2);
      final ResourcePermission permission2_withGrant = ResourcePermissions.getInstance(permissionName2, true);
      final Resource resource1_queriedDomain = accessControlContext.createResource(queriedResourceClass, queriedDomain);
      final Resource resource_unqueriedDomain = accessControlContext.createResource(queriedResourceClass,
                                                                                    generateDomain());
      final Resource resource2_queriedDomain = accessControlContext.createResource(queriedResourceClass, queriedDomain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource1_queriedDomain,
                                                  setOf(permission1_withoutGrant, permission2_withGrant));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource2_queriedDomain,
                                                  setOf(permission1_withGrant, permission2_withoutGrant));
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource_unqueriedDomain,
                                                  setOf(permission1_withoutGrant, permission2_withGrant));

      // verify as system resource
      final Set<Resource> expected_p1_withoutGrant_anyDomain = setOf(resource1_queriedDomain,
                                                                     resource_unqueriedDomain,
                                                                     resource2_queriedDomain);
      final Set<Resource> expected_p1_withGrant_queriedDomain = setOf(resource2_queriedDomain);

      Set<Resource> forAccessor_by_p1
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     permission1_withoutGrant);
      assertThat(forAccessor_by_p1, is(expected_p1_withoutGrant_anyDomain));

      forAccessor_by_p1
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(permission1_withoutGrant));
      assertThat(forAccessor_by_p1, is(expected_p1_withoutGrant_anyDomain));

      Set<Resource> forAccessor_by_p1wG
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     permission1_withGrant);
      assertThat(forAccessor_by_p1wG, is(expected_p1_withGrant_queriedDomain));

      forAccessor_by_p1wG
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(permission1_withGrant));
      assertThat(forAccessor_by_p1wG, is(expected_p1_withGrant_queriedDomain));

      Set<Resource> forAccessor_by_p1_p2wG
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     permission1_withoutGrant,
                                                                     permission2_withGrant);
      assertThat(forAccessor_by_p1_p2wG, is(setOf(resource1_queriedDomain, resource_unqueriedDomain)));

      forAccessor_by_p1_p2wG
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(permission1_withoutGrant,
                                                                           permission2_withGrant));
      assertThat(forAccessor_by_p1_p2wG, is(setOf(resource1_queriedDomain, resource_unqueriedDomain)));

      Set<Resource> forAccessor_by_p1wG_p2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     permission1_withGrant,
                                                                     permission2_withoutGrant);
      assertThat(forAccessor_by_p1wG_p2, is(setOf(resource2_queriedDomain)));

      forAccessor_by_p1wG_p2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(permission1_withGrant,
                                                                           permission2_withoutGrant));
      assertThat(forAccessor_by_p1wG_p2, is(setOf(resource2_queriedDomain)));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> forSession_by_p1
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     permission1_withoutGrant);
      assertThat(forSession_by_p1, is(expected_p1_withoutGrant_anyDomain));

      forSession_by_p1
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(permission1_withoutGrant));
      assertThat(forSession_by_p1, is(expected_p1_withoutGrant_anyDomain));

      Set<Resource> forSession_by_p1wG
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     permission1_withGrant);
      assertThat(forSession_by_p1wG, is(expected_p1_withGrant_queriedDomain));

      forSession_by_p1wG
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(permission1_withGrant));
      assertThat(forSession_by_p1wG, is(expected_p1_withGrant_queriedDomain));

      Set<Resource> forSession_by_p1_p2wG
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     permission1_withoutGrant,
                                                                     permission2_withGrant);
      assertThat(forSession_by_p1_p2wG, is(setOf(resource1_queriedDomain, resource_unqueriedDomain)));

      forSession_by_p1_p2wG
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(permission1_withoutGrant,
                                                                           permission2_withGrant));
      assertThat(forSession_by_p1_p2wG, is(setOf(resource1_queriedDomain, resource_unqueriedDomain)));

      Set<Resource> forSession_by_p1wG_p2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     permission1_withGrant,
                                                                     permission2_withoutGrant);
      assertThat(forSession_by_p1wG_p2, is(setOf(resource2_queriedDomain)));

      forSession_by_p1wG_p2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(permission1_withGrant,
                                                                           permission2_withoutGrant));
      assertThat(forSession_by_p1wG_p2, is(setOf(resource2_queriedDomain)));

   }

   @Test
   public void getResourcesByResourcePermissions_inherited_validAsAuthenticated() {
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

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions.getInstance(
                                                                           queriedPermission)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions.getInstance(
                                                                           queriedPermission)));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));
   }

   @Test
   public void getResourcesByResourcePermissions_global_validAsAuthenticated() {
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
                                                        queriedDomain,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        queriedResourceClass,
                                                        unqueriedDomain,
                                                        setOf(ResourcePermissions.getInstance(queriedPermission)));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        unqueriedResourceClass,
                                                        queriedDomain,
                                                        setOf(ResourcePermissions.getInstance(
                                                              unqueriedResourceClassPermissionName)));

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_queriedClassQueriedDomain,
                                                              resource_queriedClassUnqueriedDomain);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions.getInstance(
                                                                           queriedPermission)));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));
   }

   @Test
   public void getResourcesByResourcePermissions_domainInherited_validAsAuthenticated() {
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

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_parentDomain,
                                                              resource_childDomain1,
                                                              resource_childDomain2);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

   }

   @Test
   public void getResourcesByResourcePermissions_domainInherited_systemPermission_validAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String parentDomain = generateDomain();
      final String childDomain1 = generateChildDomain(parentDomain);
      final String childDomain2 = generateChildDomain(parentDomain);
      final String queriedResourceClass = generateResourceClass(false, false);
      final String queriedPermission = ResourcePermissions.QUERY;
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

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_parentDomain,
                                                              resource_childDomain1,
                                                              resource_childDomain2);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

   }

   @Test
   public void getResourcesByResourcePermissions_superUser_validAsAuthenticated() {
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

      final String unqueriedDomain = generateDomain();
      final String unqueriedResourceClass = generateResourceClass(false, false);
      accessControlContext.createResourcePermission(unqueriedResourceClass, unqueriedPermissionName);
      final Resource resource_unqueriedClassChildDomain
            = accessControlContext.createResource(unqueriedResourceClass, childDomain);
      final Resource resource_unqueriedClassUnqueriedDomain
            = accessControlContext.createResource(unqueriedResourceClass, unqueriedDomain);
      final Resource resource_queriedClassUnqueriedDomain
            = accessControlContext.createResource(queriedResourceClass, unqueriedDomain, PasswordCredentials.newInstance(generateUniquePassword()));

      // set super-user permission for accessor
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.setDomainPermissions(accessorResource,
                                                otherDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // verify as system resource
      final Set<Resource> expectedResources_anyDomain = setOf(resource_parentDomain,
                                                              resource_childDomain,
                                                              resource_otherDomain);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(queriedPermission)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources_anyDomain));

      // authenticate as accessor and verify
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      Set<Resource> resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     ResourcePermissions.getInstance(queriedPermission));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

      resourcesByPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     queriedResourceClass,
                                                                     setOf(ResourcePermissions.getInstance(
                                                                           queriedPermission)));
      assertThat(resourcesByPermission, is(expectedResources_anyDomain));

   }

   @Test
   public void getResourcesByResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      final String resourceClass_whitespaced = " " + resourceClass + "\t";
      final String permission_whitespaced = " " + permission + "\t";

      // verify as system resource
      final Set<Resource> expectedResources = setOf(resource);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClass_whitespaced,
                                                                     ResourcePermissions.getInstance(permission_whitespaced));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClass_whitespaced,
                                                                     setOf(ResourcePermissions.getInstance(
                                                                           permission_whitespaced)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));
   }

   @Test
   public void getResourcesByResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String resourceClass = generateResourceClass(false, false);
      final ResourcePermission resourcePermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));
      final ResourcePermission resourcePermission2
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));

      try {
         accessControlContext.getResourcesByResourcePermissions((Resource) null, resourceClass, resourcePermission);
         fail("getting resources by resource permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, null, resourcePermission);
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, resourceClass, (ResourcePermission) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, resourceClass, resourcePermission, null);
         fail("getting resources by resource permission with null resource permission sequence should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                resourceClass,
                                                                resourcePermission,
                                                                new ResourcePermission[] {null});
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource,
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
         accessControlContext.getResourcesByResourcePermissions((Resource) null, resourceClass, setOf(resourcePermission));
         fail("getting resources by resource permission with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, null, setOf(resourcePermission));
         fail("getting resources by resource permission with null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, resourceClass, (Set<ResourcePermission>) null);
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                resourceClass,
                                                                setOf(resourcePermission,
                                                                      null));
         fail("getting resources by resource permission with null resource permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void getResourcesByResourcePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String resourceClass = generateResourceClass(false, false);

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, resourceClass, Collections.<ResourcePermission>emptySet());
         fail("getting resources by resource permission with null resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void getResourcesByResourcePermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      // verify
      final Set<Resource> expectedResources = setOf(resource);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClass,
                                                                     ResourcePermissions.getInstance(permission));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));

      Set<Resource> resourcesByAccessorAndPermission2
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClass,
                                                                     ResourcePermissions.getInstance(permission),
                                                                     new ResourcePermission[] {});
      assertThat(resourcesByAccessorAndPermission2, is(expectedResources));
   }

   @Test
   public void getResourcesByResourcePermissions_duplicates_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission)));

      // verify as system resource
      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                resourceClass,
                                                                ResourcePermissions.getInstance(permission),
                                                                ResourcePermissions.getInstance(permission));
         fail("getting resources by resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void getResourcesByResourcePermissions_duplicates_shouldSucceed() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      final String domain = generateDomain();
      final String resourceClass = generateResourceClass(false, false);
      final String permission = generateResourceClassPermission(resourceClass);
      final Resource resource = accessControlContext.createResource(resourceClass, domain);

      // set permission between accessor and accessed resources
      accessControlContext.setResourcePermissions(accessorResource,
                                                  resource,
                                                  setOf(ResourcePermissions.getInstance(permission, true)));

      // verify as system resource
      final Set<Resource> expectedResources = setOf(resource);

      Set<Resource> resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClass,
                                                                     ResourcePermissions.getInstance(permission),
                                                                     ResourcePermissions.getInstance(permission, true));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));

      resourcesByAccessorAndPermission
            = accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                     resourceClass,
                                                                     setOf(ResourcePermissions
                                                                                 .getInstance(permission),
                                                                           ResourcePermissions
                                                                                 .getInstance(permission, true)));
      assertThat(resourcesByAccessorAndPermission, is(expectedResources));
   }

   @Test
   public void getResourcesByResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource nonExistentResource = Resources.getInstance(-999L);
      final String resourceClass = generateResourceClass(false, false);
      final ResourcePermission resourcePermission
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClass));
      final ResourcePermission nonExistentPermission = ResourcePermissions.getInstance("does_not_exist");

      try {
         accessControlContext.getResourcesByResourcePermissions(nonExistentResource, resourceClass, resourcePermission);
         fail("getting resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(nonExistentResource).toLowerCase() + " not found"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, "does_not_exit", resourcePermission);
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, resourceClass, nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, 
                                                                resourceClass, 
                                                                resourcePermission, 
                                                                nonExistentPermission);
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      // test set-based versions
      try {
         accessControlContext.getResourcesByResourcePermissions(nonExistentResource, resourceClass, setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(nonExistentResource).toLowerCase() + " not found"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, "does_not_exit", setOf(resourcePermission));
         fail("getting resources by resource permission with non-existent resource class name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource, resourceClass, setOf(nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.getResourcesByResourcePermissions(accessorResource,
                                                                resourceClass,
                                                                setOf(resourcePermission,
                                                                      nonExistentPermission));
         fail("getting resources by resource permission with non-existent resource permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
