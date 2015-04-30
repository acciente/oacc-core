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

import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_assertGlobalResourcePermissions extends TestAccessControlBase {
   @Test
   public void assertGlobalResourcePermissions_succeedsAsSystemResource() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // verify
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions.getInstance(customPermissionName));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions.getInstance(customPermissionName));
   }

   @Test
   public void assertGlobalResourcePermissions_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting multiple global resource permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting multiple global resource permission when none has been granted should not have succeeded for implicit authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting multiple global resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting multiple global resource permission for domain when none has been granted should not have succeeded for implicit authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_direct_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String otherDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain
            = ResourcePermissions.getInstance(customPermissionName_otherDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        otherDomainName,
                                                        setOf(customPermission_forOtherDomain));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           customPermission_forAccessorDomain);
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain);
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain);
   }

   @Test
   public void assertGlobalResourcePermissions_partialDirect_shouldFailAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String otherDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain
            = ResourcePermissions.getInstance(customPermissionName_otherDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        otherDomainName,
                                                        setOf(customPermission_forOtherDomain));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              customPermission_forAccessorDomain,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting direct and unauthorized global resource permission should have failed for implicit authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessorResource).toLowerCase()
                                                                       + " does not have global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              customPermission_forAccessorDomain,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting direct and unauthorized global resource permission should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessorResource).toLowerCase()
                                                                       + " does not have global permission"));
      }

      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              accessorDomainName,
                                                              customPermission_forAccessorDomain,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting direct and unauthorized global resource permission on specified accessor domain should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessorResource).toLowerCase()
                                                                       + " does not have global permission"));
      }

      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              otherDomainName,
                                                              customPermission_forAccessorDomain,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting direct and unauthorized global resource permission on specified domain should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessorResource).toLowerCase()
                                                                       + " does not have global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              otherDomainName,
                                                              customPermission_forAccessorDomain,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting direct and unauthorized global resource permission on specified domain should have failed for implicit authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessorResource).toLowerCase()
                                                                       + " does not have global permission"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_multipleDirect_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String otherDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(true, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain
            = ResourcePermissions.getInstance(customPermissionName_otherDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain,
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        otherDomainName,
                                                        setOf(customPermission_forOtherDomain,
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           customPermission_forAccessorDomain,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           customPermission_forAccessorDomain,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));
   }

   @Test
   public void assertGlobalResourcePermissions_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String otherDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain_withGrant
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain, true);
      final ResourcePermission customPermission_forAccessorDomain_withoutGrant
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain_withGrant
            = ResourcePermissions.getInstance(customPermissionName_otherDomain, true);
      final ResourcePermission customPermission_forOtherDomain_withoutGrant
            = ResourcePermissions.getInstance(customPermissionName_otherDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain_withGrant));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        otherDomainName,
                                                        setOf(customPermission_forOtherDomain_withoutGrant));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           customPermission_forAccessorDomain_withGrant,
                                                           customPermission_forAccessorDomain_withoutGrant);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           customPermission_forAccessorDomain_withGrant,
                                                           customPermission_forAccessorDomain_withoutGrant);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain_withGrant,
                                                           customPermission_forAccessorDomain_withoutGrant);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain_withoutGrant);
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain_withoutGrant);

      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              otherDomainName,
                                                              customPermission_forOtherDomain_withGrant);
         fail("asserting global resource permission without grant for a direct global permission (for a domain) with grant should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_resourceInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final Resource donorResource = generateUnauthenticatableResource();
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String otherDomainName = generateDomain();
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain
            = ResourcePermissions.getInstance(customPermissionName_otherDomain);

      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));

      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        otherDomainName,
                                                        setOf(customPermission_forOtherDomain));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           customPermission_forAccessorDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain);
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain);
   }

   @Test
   public void assertGlobalResourcePermissions_domainInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();
      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessorDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(accessorDomainName, intermediaryDomainName);
      final String otherDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(otherDomainName, intermediaryDomainName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password, accessorDomainName);
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_parentDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forParentDomain
            = ResourcePermissions.getInstance(customPermissionName_parentDomain);

      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain
            = ResourcePermissions.getInstance(customPermissionName_otherDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        parentDomainName,
                                                        setOf(customPermission_forParentDomain));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        otherDomainName,
                                                        setOf(customPermission_forOtherDomain));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forAccessorDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           parentDomainName,
                                                           customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           intermediaryDomainName,
                                                           customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain,
                                                           customPermission_forParentDomain);
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain,
                                                           customPermission_forParentDomain);
   }

   @Test
   public void assertGlobalResourcePermissions_domainInheritedInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();
      final String parentDomainName = generateDomain();
      final String donorDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(donorDomainName, parentDomainName);
      final Resource donorResource = generateAuthenticatableResource(generateUniquePassword(), donorDomainName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_parentDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forParentDomain
            = ResourcePermissions.getInstance(customPermissionName_parentDomain);

      final String customPermissionName_donorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forDonorDomain
            = ResourcePermissions.getInstance(customPermissionName_donorDomain);

      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        parentDomainName,
                                                        setOf(customPermission_forParentDomain));

      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        donorDomainName,
                                                        setOf(customPermission_forDonorDomain));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           parentDomainName,
                                                           customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           donorDomainName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forDonorDomain);
   }

   @Test
   public void assertGlobalResourcePermissions_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();
      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      final String accessorDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(accessorDomainName, intermediaryDomainName);
      final String otherDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(otherDomainName, intermediaryDomainName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password, accessorDomainName);
      final String resourceClassName = generateResourceClass(false, false);

      final String customPermissionName_parentDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forParentDomain
            = ResourcePermissions.getInstance(customPermissionName_parentDomain);

      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain
            = ResourcePermissions.getInstance(customPermissionName_otherDomain);

      // setup super-user domain permissions
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forAccessorDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           parentDomainName,
                                                           customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           intermediaryDomainName,
                                                           customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain,
                                                           customPermission_forParentDomain);
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain,
                                                           customPermission_forParentDomain);
   }

   @Test
   public void assertGlobalResourcePermissions_superUserInherited_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();
      final String parentDomainName = generateDomain();
      final String intermediaryDomainName = generateUniqueDomainName();
      final String accessorDomainName = generateUniqueDomainName();
      final String otherDomainName = generateUniqueDomainName();
      accessControlContext.createDomain(intermediaryDomainName, parentDomainName);
      accessControlContext.createDomain(accessorDomainName, intermediaryDomainName);
      accessControlContext.createDomain(otherDomainName, intermediaryDomainName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password, accessorDomainName);
      final String resourceClassName = generateResourceClass(false, false);

      final String customPermissionName_parentDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forParentDomain
            = ResourcePermissions.getInstance(customPermissionName_parentDomain);

      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain
            = ResourcePermissions.getInstance(customPermissionName_otherDomain);

      // setup super-user domain permissions
      final Resource donorResource = generateAuthenticatableResource(password, accessorDomainName);
      accessControlContext.setDomainPermissions(donorResource,
                                                parentDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));
      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           parentDomainName,
                                                           customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           intermediaryDomainName,
                                                           customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain,
                                                           customPermission_forParentDomain);
   }

   @Test
   public void assertGlobalResourcePermissions_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup resourceClass without any permissions
      final String resourceClassName = generateResourceClass(false, false);

      // verify
      try {
         accessControlContext
               .assertGlobalResourcePermissions(resourceClassName,
                                                ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("asserting implicit global resource permission invalid for resource class should have failed for implicit system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertGlobalResourcePermissions(SYS_RESOURCE,
                                                resourceClassName,
                                                ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("asserting implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertGlobalResourcePermissions(SYS_RESOURCE,
                                                resourceClassName,
                                                ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertGlobalResourcePermissions(SYS_RESOURCE,
                                                resourceClassName,
                                                ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit global resource permission invalid and valid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext
               .assertGlobalResourcePermissions(SYS_RESOURCE,
                                                resourceClassName,
                                                domainName,
                                                ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("asserting implicit global resource permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertGlobalResourcePermissions(SYS_RESOURCE,
                                                resourceClassName,
                                                domainName,
                                                ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit global resource permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertGlobalResourcePermissions(SYS_RESOURCE,
                                                resourceClassName,
                                                domainName,
                                                ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit global resource permission invalid and valid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .assertGlobalResourcePermissions(resourceClassName,
                                                domainName,
                                                ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting implicit global resource permission invalid and valid for resource class should have failed for implicit system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify
      accessControlContext.assertGlobalResourcePermissions(resourceClassName_whitespaced,
                                                           ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName_whitespaced,
                                                           ResourcePermissions.getInstance(customPermissionName));

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName_whitespaced,
                                                           domainName_whitespaced,
                                                           ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertGlobalResourcePermissions(resourceClassName_whitespaced,
                                                           domainName_whitespaced,
                                                           ResourcePermissions.getInstance(customPermissionName));
   }

   @Test
   public void assertGlobalResourcePermissions_whitespaceConsistent_asAuthenticatedResource() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName_forAccessorDomain = generateResourceClassPermission(resourceClassName);
      final String customPermissionName_forAccessedDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain = ResourcePermissions.getInstance(
            customPermissionName_forAccessorDomain);
      final ResourcePermission customPermission_forAccessedDomain = ResourcePermissions.getInstance(
            customPermissionName_forAccessedDomain);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String accessedDomainName = generateDomain();
      final String accessedDomainName_whitespaced = " " + accessedDomainName + "\t";

      // setup create permissions
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessedDomainName,
                                                        setOf(customPermission_forAccessedDomain));

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(resourceClassName_whitespaced,
                                                           customPermission_forAccessorDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName_whitespaced,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName_whitespaced,
                                                           accessedDomainName_whitespaced,
                                                           customPermission_forAccessedDomain);
      accessControlContext.assertGlobalResourcePermissions(resourceClassName_whitespaced,
                                                           accessedDomainName_whitespaced,
                                                           customPermission_forAccessedDomain);
   }

   @Test
   public void assertGlobalResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String customPermissionName2 = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.assertGlobalResourcePermissions((Resource) null,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(null,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for null resource class reference should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              null,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              null);
         fail("asserting global resource permission for null resource permission should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              null);
         fail("asserting global resource permission for null resource permission should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              null);
         fail("asserting global resource permission for null resource permission sequence should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              null);
         fail("asserting global resource permission for null resource permission sequence should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              new ResourcePermission[]{null});
         fail("asserting global resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              new ResourcePermission[]{null});
         fail("asserting global resource permission for null resource permission element should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              ResourcePermissions.getInstance(customPermissionName2),
                                                              null);
         fail("asserting global resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              ResourcePermissions.getInstance(customPermissionName2),
                                                              null);
         fail("asserting global resource permission for null resource permission element should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertGlobalResourcePermissions(null,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              null,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions((String) null,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for null resource class reference should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              null);
         fail("asserting global resource permission (by domain) for null resource permission should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              domainName,
                                                              null);
         fail("asserting global resource permission (by domain) for null resource permission should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              null);
         fail("asserting global resource permission (by domain) for null resource permission sequence should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              null);
         fail("asserting global resource permission (by domain) for null resource permission sequence should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              new ResourcePermission[]{null});
         fail("asserting global resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              new ResourcePermission[]{null});
         fail("asserting global resource permission for null resource permission element should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              ResourcePermissions.getInstance(customPermissionName2),
                                                              null);
         fail("asserting global resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              ResourcePermissions.getInstance(customPermissionName2),
                                                              null);
         fail("asserting global resource permission for null resource permission element should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              (String) null,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              (String) null,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for null domain reference should have failed for implicit system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);

      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           new ResourcePermission[]{});
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           new ResourcePermission[]{});

      final String domainName = generateDomain();
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                           new ResourcePermission[]{});
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                           new ResourcePermission[]{});
   }

   @Test
   public void assertGlobalResourcePermissions_duplicatePermissions_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);

      // verify
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting global resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting global resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting global resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("asserting global resource permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_duplicatePermissions_shouldSucceedAsSystemResource() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);

      // verify
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE, true));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE, true));

      final String domainName = generateDomain();
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE, true));
      accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE, true));
   }

   @Test
   public void assertGlobalResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource invalidResource = Resources.getInstance(-999L);

      try {
         accessControlContext.assertGlobalResourcePermissions(invalidResource,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for invalid accessor resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions("invalid_resource_class",
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for invalid resource class reference should have failed for implicit system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              "invalid_resource_class",
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting global resource permission for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting global resource permission for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting global resource permission for valid and invalid resource permission reference should have failed for implicit system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertGlobalResourcePermissions(invalidResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for invalid resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              "invalid_resource_class",
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              "invalid_domain",
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting global resource permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting global resource permission for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName),
                                                              ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting global resource permission for valid and invalid resource permission reference should have failed for implicit system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
   }
}