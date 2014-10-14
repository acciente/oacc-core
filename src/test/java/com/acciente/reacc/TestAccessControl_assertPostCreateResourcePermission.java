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
package com.acciente.reacc;

import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.core.IsCollectionContaining.hasItems;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_assertPostCreateResourcePermission extends TestAccessControlBase {
   @Test
   public void assertPostCreateResourcePermission_succeedsAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 ResourcePermission.getInstance(customPermissionName));
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission (even when none has been granted) should have succeeded for system resource");
      }

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 ResourcePermission.getInstance(customPermissionName),
                                                                 domainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for domain (even when none has been granted) should have succeeded for system resource");
      }
   }

   @Test
   public void assertPostCreateResourcePermission_noPermissions_shouldFailAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, password);

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 ResourcePermission.getInstance(customPermissionName));
         fail("asserting post-create resource permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("no *create permission"));
      }

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 ResourcePermission.getInstance(customPermissionName),
                                                                 domainName);
         fail("asserting post-create resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("no *create permission"));
      }
   }

   @Test
   public void assertPostCreateResourcePermission_direct_succeedsAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forAccessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain = ResourcePermission.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forAccessedDomain = ResourcePermission.getInstance(customPermissionName_forAccessedDomain);
      final String password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();

      // setup create permissions
      grantResourceCreatePermission(accessorResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(accessorResource, resourceClassName, accessedDomainName, customPermissionName_forAccessedDomain);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessorDomain = new HashSet<>();
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermission.getInstance(customPermission_forAccessorDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(resourceCreatePermissions_forAccessorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessedDomain = new HashSet<>();
      resourceCreatePermissions_forAccessedDomain.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      resourceCreatePermissions_forAccessedDomain.add(ResourceCreatePermission.getInstance(customPermission_forAccessedDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessedDomain, is(resourceCreatePermissions_forAccessedDomain));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, password);

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forAccessorDomain);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a direct create permission should have succeeded for authenticated resource");
      }

      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forAccessedDomain, accessedDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a direct create permission (for a domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void assertPostCreateResourcePermission_resourceInherited_succeedsAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forAccessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain = ResourcePermission.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forAccessedDomain = ResourcePermission.getInstance(customPermissionName_forAccessedDomain);
      final String password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource intermediaryResource = generateUnauthenticatableResource();
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();

      // setup create permissions
      grantResourceCreatePermission(intermediaryResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(intermediaryResource, resourceClassName, accessedDomainName, customPermissionName_forAccessedDomain);
      // setup inheritance permission
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource,intermediaryResource,resourcePermissions);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessorDomain = new HashSet<>();
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermission.getInstance(customPermission_forAccessorDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(intermediaryResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(resourceCreatePermissions_forAccessorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessedDomain = new HashSet<>();
      resourceCreatePermissions_forAccessedDomain.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      resourceCreatePermissions_forAccessedDomain.add(ResourceCreatePermission.getInstance(customPermission_forAccessedDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessedDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(intermediaryResource, resourceClassName, accessedDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessedDomain, is(resourceCreatePermissions_forAccessedDomain));

      final Set<ResourcePermission> allResourcePermissionsForAccessorResource
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, intermediaryResource);
      assertThat(allResourcePermissionsForAccessorResource, is(resourcePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, password);

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forAccessorDomain);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for an inherited create permission should have succeeded for authenticated resource");
      }

      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forAccessedDomain, accessedDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for an inherited create permission (for a domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void assertPostCreateResourcePermission_domainInherited_succeedsAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forIntermediaryDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain = ResourcePermission.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forIntermediaryDomain = ResourcePermission.getInstance(customPermissionName_forIntermediaryDomain);
      final String password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, accessorDomainName);
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      // setup create permissions
      grantResourceCreatePermission(accessorResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(accessorResource, resourceClassName, intermediaryDomainName, customPermissionName_forIntermediaryDomain);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forAccessorDomain = new HashSet<>();
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      resourceCreatePermissions_forAccessorDomain.add(ResourceCreatePermission.getInstance(customPermission_forAccessorDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndAccessorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndAccessorDomain, is(resourceCreatePermissions_forAccessorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forIntermediaryDomain = new HashSet<>();
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermission.getInstance(customPermission_forIntermediaryDomain, false));
      resourceCreatePermissions_forIntermediaryDomain.addAll(resourceCreatePermissions_forAccessorDomain);
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndIntermediaryDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, intermediaryDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndIntermediaryDomain, is(resourceCreatePermissions_forIntermediaryDomain));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, password);

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forAccessorDomain);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a domain-inherited create permission should have succeeded for authenticated resource");
      }

      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forAccessorDomain, accessedDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a domain-inherited create permission (for a domain) should have succeeded for authenticated resource");
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forIntermediaryDomain, accessedDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a domain-inherited create permission (for a domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void assertPostCreateResourcePermission_domainInheritedInherited_succeedsAsAuthenticatedResource() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forIntermediaryDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain = ResourcePermission.getInstance(customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forIntermediaryDomain = ResourcePermission.getInstance(customPermissionName_forIntermediaryDomain);
      final String password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final Resource donorResource = accessControlContext.createResource(generateResourceClass(false, false),accessorDomainName);
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessedDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, accessorDomainName);
      accessControlContext.createDomain(accessedDomainName, intermediaryDomainName);

      // setup create permissions
      grantResourceCreatePermission(donorResource, resourceClassName, accessorDomainName, customPermissionName_forAccessorDomain);
      grantResourceCreatePermission(donorResource, resourceClassName, intermediaryDomainName, customPermissionName_forIntermediaryDomain);
      // setup inheritance permission
      Set<ResourcePermission> inheritanceResourcePermissions = new HashSet<>();
      inheritanceResourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermissions);

      // verify permissions
      Set<ResourceCreatePermission> resourceCreatePermissions_forDonorDomain = new HashSet<>();
      resourceCreatePermissions_forDonorDomain.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      resourceCreatePermissions_forDonorDomain.add(ResourceCreatePermission.getInstance(customPermission_forAccessorDomain, false));
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDonorDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDonorDomain, is(resourceCreatePermissions_forDonorDomain));

      Set<ResourceCreatePermission> resourceCreatePermissions_forIntermediaryDomain = new HashSet<>();
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      resourceCreatePermissions_forIntermediaryDomain.add(ResourceCreatePermission.getInstance(customPermission_forIntermediaryDomain, false));
      resourceCreatePermissions_forIntermediaryDomain.addAll(resourceCreatePermissions_forDonorDomain);
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndIntermediaryDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(donorResource, resourceClassName, intermediaryDomainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndIntermediaryDomain, is(resourceCreatePermissions_forIntermediaryDomain));

      final Set<ResourcePermission> allResourcePermissionsForAccessorResource
            = accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource);
      assertThat(allResourcePermissionsForAccessorResource, is(inheritanceResourcePermissions));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, password);

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forAccessorDomain);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a domain-inherited create permission should have succeeded for authenticated resource");
      }

      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forAccessorDomain, accessedDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a domain-inherited create permission (for a domain) should have succeeded for authenticated resource");
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName, customPermission_forIntermediaryDomain, accessedDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a domain-inherited create permission (for a domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void assertPostCreateResourcePermission_globalOnly_shouldFailAsAuthenticatedResource() throws AccessControlException {
      // special case where the requested permission hasn't been granted as a create permission
      // but will be available from the granted global permissions on the resource class - domain tuple
      // Note that in this test case there is no *CREATE permission, and the test thus should fail
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermission.getInstance(customPermissionName);
      final String password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      // setup create permission
      //Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      //final ResourceCreatePermission createPermission_create = ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false);
      //resourceCreatePermissions.add(createPermission_create);
      //accessControlContext.setResourceCreatePermissions(accessorResource,
      //                                                  resourceClassName,
      //                                                  resourceCreatePermissions,
      //                                                  accessorDomainName);
      // setup global permission
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(globalResourcePermission);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        globalResourcePermissions,
                                                        accessorDomainName);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      final Set<ResourcePermission> allGlobalResourcePermissionsForResourceClass
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allGlobalResourcePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allGlobalResourcePermissionsForResourceClass, hasItem(globalResourcePermission));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, password);

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 globalResourcePermission);
         fail("asserting post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("no *create permission"));
      }

      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 globalResourcePermission,
                                                                 accessorDomainName);
         fail("asserting post-create resource permission without *CREATE should not have succeeded for authenticated resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("no *create permission"));
      }
   }

   @Test
   public void assertPostCreateResourcePermission_globalAndDirect_succeedsAsAuthenticatedResource() throws AccessControlException {
      // special case where some of the requested permission haven't been granted as a create permission
      // but will be available from the granted global permissions on the resource class - domain tuple
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final ResourcePermission globalResourcePermission = ResourcePermission.getInstance(globalPermissionName);
      final ResourcePermission customResourcePermission = ResourcePermission.getInstance(customPermissionName);
      final ResourcePermission systemResourcePermission = ResourcePermission.getInstance(ResourcePermission.RESET_PASSWORD);
      final String password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      // setup direct resource create permissions
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      final ResourceCreatePermission createPermission_create = ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false);
      final ResourceCreatePermission createPermission_custom = ResourceCreatePermission.getInstance(customResourcePermission, false);
      final ResourceCreatePermission createPermission_system = ResourceCreatePermission.getInstance(systemResourcePermission, false);
      resourceCreatePermissions.add(createPermission_create);
      resourceCreatePermissions.add(createPermission_custom);
      resourceCreatePermissions.add(createPermission_system);
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        resourceClassName,
                                                        resourceCreatePermissions,
                                                        accessorDomainName);
      // setup global permission
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(globalResourcePermission);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        globalResourcePermissions,
                                                        accessorDomainName);

      // verify permissions
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allResourceCreatePermissionsForResourceClass.size(), is(3));
      assertThat(allResourceCreatePermissionsForResourceClass, hasItems(createPermission_create, createPermission_custom, createPermission_system));

      final Set<ResourcePermission> allGlobalResourcePermissionsForResourceClass
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessorDomainName);
      assertThat(allGlobalResourcePermissionsForResourceClass.isEmpty(), is(false));
      assertThat(allGlobalResourcePermissionsForResourceClass, hasItem(globalResourcePermission));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, password);

      // verify
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 globalResourcePermission);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a global permission should have succeeded for authenticated resource");
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 customResourcePermission);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a direct permission should have succeeded for authenticated resource");
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 systemResourcePermission);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a system permission should have succeeded for authenticated resource");
      }

      // verify by domain
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 globalResourcePermission,
                                                                 accessorDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a global permission (for a domain) should have succeeded for authenticated resource");
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 customResourcePermission,
                                                                 accessorDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a direct permission (for a domain) should have succeeded for authenticated resource");
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 systemResourcePermission,
                                                                 accessorDomainName);
      }
      catch (AccessControlException e) {
         fail("asserting post-create resource permission for a system permission (for a domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void assertPostCreateResourcePermission_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.assertPostCreateResourcePermission(null,
                                                                 ResourcePermission.getInstance(customPermissionName));
         fail("asserting post-create resource permission for null resource class reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 null);
         fail("asserting post-create resource permission for null resource permission reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertPostCreateResourcePermission(null,
                                                                 ResourcePermission.getInstance(customPermissionName),
                                                                 domainName);
         fail("asserting post-create resource permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 null,
                                                                 domainName);
         fail("asserting post-create resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 ResourcePermission.getInstance(customPermissionName),
                                                                 null);
         fail("asserting post-create resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void assertPostCreateResourcePermission_nonExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.assertPostCreateResourcePermission("invalid_resource_class",
                                                                 ResourcePermission.getInstance(customPermissionName));
         fail("asserting post-create resource permission for invalid resource class reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 ResourcePermission.getInstance("invalid_permission"));
         fail("asserting post-create resource permission for invalid resource permission reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertPostCreateResourcePermission("invalid_resource_class",
                                                                 ResourcePermission.getInstance(customPermissionName),
                                                                 domainName);
         fail("asserting post-create resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 ResourcePermission.getInstance("invalid_permission"),
                                                                 domainName);
         fail("asserting post-create resource permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertPostCreateResourcePermission(resourceClassName,
                                                                 ResourcePermission.getInstance(customPermissionName),
                                                                 "invalid_domain");
         fail("asserting post-create resource permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(false));
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
