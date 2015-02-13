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

public class TestAccessControl_assertGlobalResourcePermission extends TestAccessControlBase {
   @Test
   public void assertGlobalResourcePermission_succeedsAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // verify
      accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance(customPermissionName));

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance(customPermissionName),
                                                          domainName);
   }

   @Test
   public void assertGlobalResourcePermission_noPermissions_shouldFailAsAuthenticated() throws AccessControlException {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
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
         accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission when none has been granted should not have succeeded for authenticated resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("no global permission"));
      }

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      try {
         accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName),
                                                             domainName);
         fail("asserting global resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("no global permission"));
      }
   }

   @Test
   public void assertGlobalResourcePermission_direct_succeedsAsAuthenticatedResource() throws AccessControlException {
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
                                                        setOf(customPermission_forAccessorDomain),
                                                        accessorDomainName);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        setOf(customPermission_forOtherDomain),
                                                        otherDomainName);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forOtherDomain,
                                                          otherDomainName);
   }

   @Test
   public void assertGlobalResourcePermission_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() throws AccessControlException {
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
                                                        setOf(customPermission_forAccessorDomain_withGrant),
                                                        accessorDomainName);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        setOf(customPermission_forOtherDomain_withoutGrant),
                                                        otherDomainName);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain_withGrant);
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain_withoutGrant);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain_withGrant,
                                                          accessorDomainName);
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain_withoutGrant,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forOtherDomain_withoutGrant,
                                                          otherDomainName);
      try {
         accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                             resourceClassName,
                                                             customPermission_forOtherDomain_withGrant,
                                                             otherDomainName);
         fail("asserting global resource permission without grant for a direct global permission (for a domain) with grant should have succeeded for authenticated resource");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("no global permission"));
      }
   }

   @Test
   public void assertGlobalResourcePermission_resourceInherited_succeedsAsAuthenticatedResource() throws AccessControlException {
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
                                                        setOf(customPermission_forAccessorDomain),
                                                        accessorDomainName);

      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        setOf(customPermission_forOtherDomain),
                                                        otherDomainName);

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forOtherDomain,
                                                          otherDomainName);
   }

   @Test
   public void assertGlobalResourcePermission_domainInherited_succeedsAsAuthenticatedResource() throws AccessControlException {
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
                                                        setOf(customPermission_forParentDomain),
                                                        parentDomainName);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        setOf(customPermission_forAccessorDomain),
                                                        accessorDomainName);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        setOf(customPermission_forOtherDomain),
                                                        otherDomainName);

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          parentDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          intermediaryDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forOtherDomain,
                                                          otherDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          otherDomainName);
   }

   @Test
   public void assertGlobalResourcePermission_domainInheritedInherited_succeedsAsAuthenticatedResource() throws AccessControlException {
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
                                                        setOf(customPermission_forParentDomain),
                                                        parentDomainName);

      accessControlContext.setGlobalResourcePermissions(donorResource,
                                                        resourceClassName,
                                                        setOf(customPermission_forDonorDomain),
                                                        donorDomainName);

      // setup accessor --INHERIT-> donor
      accessControlContext.setResourcePermissions(accessorResource,
                                                  donorResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          parentDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          donorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forDonorDomain,
                                                          donorDomainName);
   }

   @Test
   public void assertGlobalResourcePermission_superUser_succeedsAsAuthenticatedResource() throws AccessControlException {
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
      accessControlContext.setDomainPermissions(accessorResource,
                                                parentDomainName,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          parentDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          intermediaryDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forOtherDomain,
                                                          otherDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          otherDomainName);
   }

   @Test
   public void assertGlobalResourcePermission_superUserInherited_succeedsAsAuthenticatedResource() throws AccessControlException {
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
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          parentDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          intermediaryDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forAccessorDomain,
                                                          accessorDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forOtherDomain,
                                                          otherDomainName);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName,
                                                          customPermission_forParentDomain,
                                                          otherDomainName);
   }

   @Test
   public void assertGlobalResourcePermission_whitespaceConsistent() throws AccessControlException {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify
      accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName_whitespaced,
                                                          ResourcePermissions.getInstance(customPermissionName));

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName_whitespaced,
                                                          ResourcePermissions.getInstance(customPermissionName),
                                                          domainName_whitespaced);
   }

   @Test
   public void assertGlobalResourcePermission_whitespaceConsistent_asAuthenticatedResource() throws AccessControlException {
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
                                                        setOf(customPermission_forAccessorDomain),
                                                        accessorDomainName);
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        setOf(customPermission_forAccessedDomain),
                                                        accessedDomainName);

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName_whitespaced,
                                                          customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermission(accessorResource,
                                                          resourceClassName_whitespaced,
                                                          customPermission_forAccessedDomain,
                                                          accessedDomainName_whitespaced);
   }

   @Test
   public void assertGlobalResourcePermission_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.assertGlobalResourcePermission(null,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             null,
                                                             ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             resourceClassName,
                                                             null);
         fail("asserting global resource permission for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertGlobalResourcePermission(null,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName),
                                                             domainName);
         fail("asserting global resource permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             null,
                                                             ResourcePermissions.getInstance(customPermissionName),
                                                             domainName);
         fail("asserting global resource permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             resourceClassName,
                                                             null,
                                                             domainName);
         fail("asserting global resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName),
                                                             null);
         fail("asserting global resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void assertGlobalResourcePermission_nonExistentReferences_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.assertGlobalResourcePermission(Resources.getInstance(-999L),
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for invalid accessor resource reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("no global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             "invalid_resource_class",
                                                             ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance("invalid_permission"));
         fail("asserting global resource permission for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.assertGlobalResourcePermission(Resources.getInstance(-999L),
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName),
                                                             domainName);
         fail("asserting global resource permission (by domain) for invalid resource reference should have failed for system resource");
      }
      catch (AccessControlException e) {
         assertThat(e.isNotAuthorizedError(), is(true));
         assertThat(e.getMessage().toLowerCase(), containsString("no global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             "invalid_resource_class",
                                                             ResourcePermissions.getInstance(customPermissionName),
                                                             domainName);
         fail("asserting global resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance("invalid_permission"),
                                                             domainName);
         fail("asserting global resource permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermission(SYS_RESOURCE,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName),
                                                             "invalid_domain");
         fail("asserting global resource permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
