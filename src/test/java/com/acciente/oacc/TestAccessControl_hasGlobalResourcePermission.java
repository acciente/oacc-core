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

import org.junit.Ignore;
import org.junit.Test;

import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_hasGlobalResourcePermission extends TestAccessControlBase {
   @Test
   public void hasGlobalResourcePermission_succeedsAsSystemResource() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClass
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName);
      assertThat(allResourceCreatePermissionsForResourceClass.isEmpty(), is(true));

      // verify
      if (!accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking implicit global resource permission as system resource should have succeeded");
      }

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      if (!accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance(customPermissionName),
                                                          domainName)) {
         fail("checking implicit global resource permission for a specified domain as system resource should have succeeded");
      }
   }

   @Test
   public void hasGlobalResourcePermission_noPermissions_shouldFailAsAuthenticated() {
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
      if (accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking global resource permission when none has been granted should not have succeeded for authenticated resource");
      }

      final String domainName = generateDomain();
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      if (accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                             resourceClassName,
                                                             ResourcePermissions.getInstance(customPermissionName),
                                                             domainName)) {
         fail("checking global resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_direct_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain)) {
         fail("checking direct global resource permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain,
                                                            accessorDomainName)) {
         fail("checking direct global resource permission on specified accessor domain should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forOtherDomain,
                                                            otherDomainName)) {
         fail("checking direct global resource permission on specified domain should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_directWithDifferentGrantingRights_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain_withGrant)) {
         fail("checking global resource permission with grant for a direct global permission with grant should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain_withoutGrant)) {
         fail("checking global resource permission without grant for a direct global permission with grant should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain_withGrant,
                                                            accessorDomainName)) {
         fail("checking global resource permission with grant for a direct global permission (for a domain) with grant should have succeeded for authenticated resource");
      }
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain_withoutGrant,
                                                            accessorDomainName)) {
         fail("checking global resource permission without grant for a direct global permission (for a domain) with grant should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forOtherDomain_withoutGrant,
                                                            otherDomainName)) {
         fail("checking global resource permission without grant for a direct global permission (for a domain) without grant should have succeeded for authenticated resource");
      }

      if (accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                           resourceClassName,
                                                           customPermission_forOtherDomain_withGrant,
                                                           otherDomainName)) {
         fail("checking global resource permission with grant for a direct global permission (for a domain) without grant should have failed for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_resourceInherited_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain)) {
         fail("checking inherited global resource permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain,
                                                            accessorDomainName)) {
         fail("checking inherited global resource permission (for accessor's domain) should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forOtherDomain,
                                                            otherDomainName)) {
         fail("checking inherited global resource permission (for a domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_domainInherited_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain)) {
         fail("checking domain-inherited global resource permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain)) {
         fail("checking direct global resource permission in presence of domain-inherited permissions should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            parentDomainName)) {
         fail("checking direct global resource permission (for a domain) should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            intermediaryDomainName)) {
         fail("checking domain-inherited global resource permission (for child domain) should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            accessorDomainName)) {
         fail("checking domain-inherited global resource permission (for child domain) should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain,
                                                            accessorDomainName)) {
         fail("checking direct global resource permission in presence of domain-inherited permissions (for child domain) should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forOtherDomain,
                                                            otherDomainName)) {
         fail("checking direct global resource permission in presences of domain-inherited permissions (for sibling domain) should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            otherDomainName)) {
         fail("checking domain-inherited global resource permission (for sibling domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_domainInheritedInherited_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            parentDomainName)) {
         fail("checking direct global resource permission in presence of inherited domain-inherited permissions (on parent domain) should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            donorDomainName)) {
         fail("checking inherited domain-inherited global resource permission (on child domain) should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forDonorDomain,
                                                            donorDomainName)) {
         fail("checking direct global resource permission in presence of inherited domain-inherited permissions (on child domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_superUser_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain)) {
         fail("checking implicit domain-inherited global resource permission when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain)) {
         fail("checking implicit global resource permission when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            parentDomainName)) {
         fail("checking implicit domain-inherited global resource permission (on parent domain) when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            intermediaryDomainName)) {
         fail("checking implicit domain-inherited global resource permission (on intermediary domain) when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            accessorDomainName)) {
         fail("checking implicit domain-inherited global resource permission (on accessor domain) when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain,
                                                            accessorDomainName)) {
         fail("checking implicit global resource permission (on accessor domain) when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forOtherDomain,
                                                            otherDomainName)) {
         fail("checking implicit global resource permission (on sibling domain) when having super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            otherDomainName)) {
         fail("checking implicit domain-inherited global resource permission (on sibling domain) when having super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_superUserInherited_succeedsAsAuthenticatedResource() {
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
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain)) {
         fail("checking implicit domain-inherited global resource permission when having inherited super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain)) {
         fail("checking implicit global resource permission when having inherited super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            parentDomainName)) {
         fail("checking implicit domain-inherited global resource permission (on parent domain) when having inherited super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            intermediaryDomainName)) {
         fail("checking implicit domain-inherited global resource permission (on intermediary domain) when having inherited super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            accessorDomainName)) {
         fail("checking implicit domain-inherited global resource permission (on accessor domain) when having inherited super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forAccessorDomain,
                                                            accessorDomainName)) {
         fail("checking implicit global resource permission (on accessor domain) when having inherited super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forOtherDomain,
                                                            otherDomainName)) {
         fail("checking implicit global resource permission (on sibling domain) when having inherited super-user privileges should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName,
                                                            customPermission_forParentDomain,
                                                            otherDomainName)) {
         fail("checking implicit domain-inherited global resource permission (on sibling domain) when having inherited super-user privileges should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup resourceClass without any permissions
      final String resourceClassName = generateResourceClass(false, false);

      // verify
      try {
         accessControlContext
               .hasGlobalResourcePermission(SYS_RESOURCE,
                                            resourceClassName,
                                            ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("checking implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasGlobalResourcePermission(SYS_RESOURCE,
                                            resourceClassName,
                                            ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
         fail("checking implicit global resource permission invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext
               .hasGlobalResourcePermission(SYS_RESOURCE,
                                            resourceClassName,
                                            ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS),
                                            domainName);
         fail("checking implicit global resource permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
      try {
         accessControlContext
               .hasGlobalResourcePermission(SYS_RESOURCE,
                                            resourceClassName,
                                            ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                            domainName);
         fail("checking implicit global resource permission (for a domain) invalid for resource class should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource class"));
      }
   }

   @Test
   public void hasGlobalResourcePermission_whitespaceConsistent() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(false, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      // verify
      if (!accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                            resourceClassName_whitespaced,
                                                            ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking whitespaced global resource permission should have succeeded for system resource");
      }

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(SYS_RESOURCE, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));
      if (!accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                            resourceClassName_whitespaced,
                                                            ResourcePermissions.getInstance(customPermissionName),
                                                            domainName_whitespaced)) {
         fail("checking whitespaced global resource permission (on a whitespaced domain) should have succeeded for system resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_whitespaceConsistent_asAuthenticatedResource() {
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
      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName_whitespaced,
                                                            customPermission_forAccessorDomain)) {
         fail("checking whitespaced global resource permission should have succeeded for authenticated resource");
      }

      if (!accessControlContext.hasGlobalResourcePermission(accessorResource,
                                                            resourceClassName_whitespaced,
                                                            customPermission_forAccessedDomain,
                                                            accessedDomainName_whitespaced)) {
         fail("checking whitespaced global resource permission (on a whitespaced domain) should have succeeded for authenticated resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_nulls_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.hasGlobalResourcePermission(null,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance(customPermissionName));
         fail("checking global resource permission for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          null,
                                                          ResourcePermissions.getInstance(customPermissionName));
         fail("checking global resource permission for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          null);
         fail("checking global resource permission for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.hasGlobalResourcePermission(null,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance(customPermissionName),
                                                          domainName);
         fail("checking global resource permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          null,
                                                          ResourcePermissions.getInstance(customPermissionName),
                                                          domainName);
         fail("checking global resource permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          null,
                                                          domainName);
         fail("checking global resource permission (by domain) for null resource permission reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource permission required"));
      }
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance(customPermissionName),
                                                          null);
         fail("checking global resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void hasGlobalResourcePermission_nonExistentReferences_shouldSucceed() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      if (accessControlContext.hasGlobalResourcePermission(Resources.getInstance(-999L),
                                                           resourceClassName,
                                                           ResourcePermissions.getInstance(customPermissionName))) {
         fail("checking global resource permission for invalid accessor resource reference should have failed for system resource");
      }

      final String domainName = generateDomain();
      if (accessControlContext.hasGlobalResourcePermission(Resources.getInstance(-999L),
                                                           resourceClassName,
                                                           ResourcePermissions.getInstance(customPermissionName),
                                                           domainName)) {
         fail("checking global resource permission (by domain) for invalid resource reference should have failed for system resource");
      }
   }

   @Test
   public void hasGlobalResourcePermission_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);

      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          "invalid_resource_class",
                                                          ResourcePermissions.getInstance(customPermissionName));
         fail("checking global resource permission for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance("invalid_permission"));
         fail("checking global resource permission for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      final String domainName = generateDomain();
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          "invalid_resource_class",
                                                          ResourcePermissions.getInstance(customPermissionName),
                                                          domainName);
         fail("checking global resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance("invalid_permission"),
                                                          domainName);
         fail("checking global resource permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.hasGlobalResourcePermission(SYS_RESOURCE,
                                                          resourceClassName,
                                                          ResourcePermissions.getInstance(customPermissionName),
                                                          "invalid_domain");
         fail("checking global resource permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
