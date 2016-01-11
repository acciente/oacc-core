/*
 * Copyright 2009-2016, Acciente LLC
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
      final String domainName = generateDomain();

      // verify
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions.getInstance(customPermissionName));

      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions.getInstance(customPermissionName)));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                                 ResourcePermissions.getInstance(customPermissionName)));
   }

   @Test
   public void assertGlobalResourcePermissions_noPermissions_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource accessorResource = generateAuthenticatableResource(password);
      final String domainName = generateDomain();

      // authenticate accessor/creator resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify setup
      final Set<ResourceCreatePermission> allResourceCreatePermissionsForResourceClassAndDomain
            = accessControlContext.getEffectiveResourceCreatePermissions(accessorResource, resourceClassName, domainName);
      assertThat(allResourceCreatePermissionsForResourceClassAndDomain.isEmpty(), is(true));

      // verify
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
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                                    ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting multiple global resource permission for domain when none has been granted should not have succeeded for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_withoutQueryAuthorization_shouldFailAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));

      // authenticate resource without query authorization
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              accessorDomainName,
                                                              customPermission_forAccessorDomain);
         fail("asserting global permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }

      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              accessorDomainName,
                                                              setOf(customPermission_forAccessorDomain));
         fail("asserting global permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));

      // authenticate accessor resource with implicit query authorization
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forAccessorDomain));
   }

   @Test
   public void assertGlobalResourcePermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));

      // authenticate accessor resource with query authorization
      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forAccessorDomain));
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
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forAccessorDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain);

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forOtherDomain));
   }

   @Test
   public void assertGlobalResourcePermissions_direct_withExtId() {
      authenticateSystemResource();

      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      final String accessorDomainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String resourceClassName = generateResourceClass(false, false);

      // setup global permissions
      final String customPermissionName_accessorDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forAccessorDomain
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessorDomainName,
                                                        setOf(customPermission_forAccessorDomain));

      // verify
      accessControlContext.assertGlobalResourcePermissions(Resources.getInstance(externalId),
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain);

      accessControlContext.assertGlobalResourcePermissions(Resources.getInstance(externalId),
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forAccessorDomain));
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
                                                              accessorDomainName,
                                                              setOf(customPermission_forAccessorDomain,
                                                                    ResourcePermissions
                                                                          .getInstance(ResourcePermissions.IMPERSONATE)));
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
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              otherDomainName,
                                                              setOf(customPermission_forAccessorDomain,
                                                                    ResourcePermissions
                                                                          .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("asserting direct and unauthorized global resource permission on specified domain should have failed for authenticated resource");
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
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forAccessorDomain,
                                                                 ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE)));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forOtherDomain,
                                                                 ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE)));
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
            = ResourcePermissions.getInstanceWithGrantOption(customPermissionName_accessorDomain);
      final ResourcePermission customPermission_forAccessorDomain_withoutGrant
            = ResourcePermissions.getInstance(customPermissionName_accessorDomain);

      final String customPermissionName_otherDomain = generateResourceClassPermission(resourceClassName);
      final ResourcePermission customPermission_forOtherDomain_withGrant
            = ResourcePermissions.getInstanceWithGrantOption(customPermissionName_otherDomain);
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
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain_withGrant,
                                                           customPermission_forAccessorDomain_withoutGrant);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forAccessorDomain_withGrant,
                                                                 customPermission_forAccessorDomain_withoutGrant));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain_withoutGrant);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forOtherDomain_withoutGrant));

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
      try {
         accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              otherDomainName,
                                                              setOf(customPermission_forOtherDomain_withGrant));
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
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           customPermission_forAccessorDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forAccessorDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           customPermission_forOtherDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forOtherDomain));
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

      // test set-based versions
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           parentDomainName,
                                                           setOf(customPermission_forParentDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           intermediaryDomainName,
                                                           setOf(customPermission_forParentDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forParentDomain,
                                                                 customPermission_forAccessorDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forOtherDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forParentDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forOtherDomain,
                                                                 customPermission_forParentDomain));
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
                                                           parentDomainName,
                                                           setOf(customPermission_forParentDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           donorDomainName,
                                                           customPermission_forParentDomain,
                                                           customPermission_forDonorDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           donorDomainName,
                                                           setOf(customPermission_forParentDomain,
                                                                 customPermission_forDonorDomain));
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

      // verify
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           parentDomainName,
                                                           setOf(customPermission_forParentDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           intermediaryDomainName,
                                                           setOf(customPermission_forParentDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forParentDomain,
                                                                 customPermission_forAccessorDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forOtherDomain,
                                                                 customPermission_forParentDomain));
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

      // test set-based versions
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           parentDomainName,
                                                           setOf(customPermission_forParentDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           intermediaryDomainName,
                                                           setOf(customPermission_forParentDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           accessorDomainName,
                                                           setOf(customPermission_forParentDomain,
                                                                 customPermission_forAccessorDomain));

      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           otherDomainName,
                                                           setOf(customPermission_forOtherDomain,
                                                                 customPermission_forParentDomain));
   }

   @Test
   public void assertGlobalResourcePermissions_superUserInvalidPermission_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup resourceClass without any permissions
      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      // verify
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

      // test set-based version
      try {
         accessControlContext
               .assertGlobalResourcePermissions(SYS_RESOURCE,
                                                resourceClassName,
                                                domainName,
                                                setOf(ResourcePermissions
                                                            .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
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
                                                setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));
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
                                                setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                      ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));
         fail("asserting implicit global resource permission invalid and valid for resource class should have failed for system resource");
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
      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";

      // verify
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName_whitespaced,
                                                           domainName_whitespaced,
                                                           ResourcePermissions.getInstance(customPermissionName));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName_whitespaced,
                                                           domainName_whitespaced,
                                                           setOf(ResourcePermissions.getInstance(customPermissionName)));
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
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName_whitespaced,
                                                           accessedDomainName_whitespaced,
                                                           customPermission_forAccessedDomain);
      accessControlContext.assertGlobalResourcePermissions(accessorResource,
                                                           resourceClassName_whitespaced,
                                                           accessedDomainName_whitespaced,
                                                           setOf(customPermission_forAccessedDomain));
   }

   @Test
   public void assertGlobalResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String customPermissionName2 = generateResourceClassPermission(resourceClassName);
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
         accessControlContext.assertGlobalResourcePermissions(Resources.getInstance(null),
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for null internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
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
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              (ResourcePermission) null);
         fail("asserting global resource permission (by domain) for null resource permission should have failed for system resource");
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
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              (String) null,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      // test set-based versions
      try {
         accessControlContext.assertGlobalResourcePermissions(null,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for null accessor resource reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(Resources.getInstance(null),
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for null internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              null,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for null resource class reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              (Set<ResourcePermission>) null);
         fail("asserting global resource permission (by domain) for null resource permission should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(customPermissionName),
                                                                    null));
         fail("asserting global resource permission for null resource permission element should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              (String) null,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for null domain reference should have failed for system resource");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String domainName = generateDomain();

      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              Collections.<ResourcePermission>emptySet());
         fail("asserting global resource permission (by domain) for null resource permission should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void assertGlobalResourcePermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(true, false);
      final String domainName = generateDomain();

      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                                                           new ResourcePermission[]{});
   }

   @Test
   public void assertGlobalResourcePermissions_duplicatePermissions_shouldFailAsSystemResource() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);
      final String domainName = generateDomain();

      // verify
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
   }

   @Test
   public void assertGlobalResourcePermissions_duplicatePermissions_shouldSucceedAsSystemResource() {
      authenticateSystemResource();
      // setup permission without granting it to anything
      final String resourceClassName = generateResourceClass(true, false);
      final String domainName = generateDomain();

      // verify
      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE));

      accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE),
                                                                 ResourcePermissions
                                                                       .getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE)));
   }

   @Test
   public void assertGlobalResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");
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
         accessControlContext.assertGlobalResourcePermissions(invalidExternalResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for invalid external resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(mismatchedResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for mismatched internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              "invalid_resource_class",
                                                              domainName,
                                                              ResourcePermissions.getInstance(customPermissionName));
         fail("asserting global resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
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

      // test set-based version
      try {
         accessControlContext.assertGlobalResourcePermissions(invalidResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for invalid resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(invalidExternalResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for invalid external resource reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(mismatchedResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for mismatched internal/external resource references should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              "invalid_resource_class",
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for invalid resource class reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              "invalid_domain",
                                                              setOf(ResourcePermissions.getInstance(customPermissionName)));
         fail("asserting global resource permission (by domain) for invalid domain reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance("invalid_permission")));
         fail("asserting global resource permission (by domain) for invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.assertGlobalResourcePermissions(SYS_RESOURCE,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(customPermissionName),
                                                                    ResourcePermissions.getInstance("invalid_permission")));
         fail("asserting global resource permission for valid and invalid resource permission reference should have failed for system resource");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
   }
}