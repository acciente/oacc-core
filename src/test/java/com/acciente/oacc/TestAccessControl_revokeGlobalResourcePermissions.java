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
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_revokeGlobalResourcePermissions extends TestAccessControlBase {
   @Test
   public void revokeGlobalResourcePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup permissions
      final String permissionName = generateResourceClassPermission(authenticatableResourceClassName);
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(permissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        domainName,
                                                        permissions_pre);

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            authenticatableResourceClassName,
                                                                            domainName),
                 is(permissions_pre));

      // revoke permissions and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           authenticatableResourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstance(permissionName));

      // reset for implicit domain
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        permissions_pre);

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            authenticatableResourceClassName,
                                                                            domainName),
                 is(permissions_pre));

      // revoke permissions and verify for implicit domain
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           authenticatableResourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post_implicit
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName);
      assertThat(permissions_post_implicit.isEmpty(), is(true));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        authenticatableResourceClassName,
                                                        domainName,
                                                        permissions_pre);

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            authenticatableResourceClassName,
                                                                            domainName),
                 is(permissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           authenticatableResourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE),
                                                                 ResourcePermissions
                                                                       .getInstance(permissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            authenticatableResourceClassName,
                                                                            domainName).isEmpty(),
                 is(true));

      // reset for implicit domain
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        authenticatableResourceClassName,
                                                        permissions_pre);

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            authenticatableResourceClassName,
                                                                            domainName),
                 is(permissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           authenticatableResourceClassName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE),
                                                                 ResourcePermissions
                                                                       .getInstance(permissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2,
                                                                            authenticatableResourceClassName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_ungrantedPermissions_shouldSucceed() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName = generateResourceClassPermission(authenticatableResourceClassName);

      // revoke permissions and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           authenticatableResourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, domainName);
      assertThat(permissions_post_specific.isEmpty(), is(true));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           authenticatableResourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE),
                                                                 ResourcePermissions
                                                                       .getInstance(permissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            authenticatableResourceClassName,
                                                                            domainName).isEmpty(),
                 is(true));

      // revoke permissions and verify for implicit domain
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           authenticatableResourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions
                                                                 .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post_implicit
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName);
      assertThat(permissions_post_implicit.isEmpty(), is(true));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           authenticatableResourceClassName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE),
                                                                 ResourcePermissions
                                                                       .getInstance(permissionName)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            authenticatableResourceClassName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_ungrantedPermissions_withAndWithoutGrant_shouldFail() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final String grantablePermissionName = generateResourceClassPermission(authenticatableResourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        authenticatableResourceClassName,
                                                        domainName,
                                                        setOf(ResourcePermissions.getInstance(grantablePermissionName,
                                                                                              true)));

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            authenticatableResourceClassName,
                                                                            domainName),
                 is(setOf(ResourcePermissions.getInstance(grantablePermissionName, true))));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke permissions and verify
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              authenticatableResourceClassName,
                                                              domainName,
                                                              ResourcePermissions
                                                                    .getInstance(grantablePermissionName),
                                                              ResourcePermissions
                                                                    .getInstance(ungrantablePermissionName));
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              authenticatableResourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(grantablePermissionName),
                                                                    ResourcePermissions
                                                                          .getInstance(ungrantablePermissionName)));
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            authenticatableResourceClassName,
                                                                            domainName),
                 is(setOf(ResourcePermissions.getInstance(grantablePermissionName, true))));

      // revoke permissions and verify for implicit domain
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              authenticatableResourceClassName,
                                                              ResourcePermissions
                                                                    .getInstance(grantablePermissionName),
                                                              ResourcePermissions
                                                                    .getInstance(ungrantablePermissionName));
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              authenticatableResourceClassName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(grantablePermissionName),
                                                                    ResourcePermissions
                                                                          .getInstance(ungrantablePermissionName)));
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_ungrantedInheritSystemPermission_shouldSucceed() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke *INHERIT system permission
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT));
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.INHERIT));
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.INHERIT)));
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.INHERIT)));
   }

   @Test
   public void revokeGlobalResourcePermissions_ungrantedResetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke *RESET_CREDENTIALS system permission
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("revoking reset-credentials permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("revoking reset-credentials permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("revoking reset-credentials permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("revoking reset-credentials permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_ungrantedImpersonatePermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke *IMPERSONATE system permission
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("revoking impersonate permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE));
         fail("revoking impersonate permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("revoking impersonate permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(ResourcePermissions.IMPERSONATE)));
         fail("revoking impersonate permission for unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_validAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);

      // setup permissions
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(customPermissionName));

      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        permissions_pre);

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(permissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        permissions_pre);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke global permissions as grantor and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions.getInstance(customPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(permissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE),
                                                                 ResourcePermissions.getInstance(customPermissionName)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_validWithDefaultSessionDomain() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);

      // set permissions
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(customPermissionName));
      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName),
                 is(permissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            grantorDomainName), is(
            grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke global permissions as grantor and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE),
                                                           ResourcePermissions.getInstance(customPermissionName));

      final Set<ResourcePermission> permissions_post_explicit = accessControlContext
            .getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_explicit.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, grantorDomainName),
                 is(permissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE),
                                                                 ResourcePermissions.getInstance(customPermissionName)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, grantorDomainName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_reRevokePermissions() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // set permissions
      final String permissionName = generateResourceClassPermission(resourceClassName);
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true),
                    ResourcePermissions.getInstance(permissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        permissions_pre);

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(permissions_pre));

      // revoke permissions and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE, true),
                                                           ResourcePermissions
                                                                 .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post1 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post1.isEmpty(), is(true));

      // revoke permission again and verify nothing changed
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions
                                                                 .getInstance(permissionName));

      final Set<ResourcePermission> permissions_post2 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post2.isEmpty(), is(true));

      // revoke permission again via set-based version and verify nothing changed
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions.getInstance(permissionName)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_revokeSubsetOfPermissions() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String grantorDomainName = accessControlContext.getDomainNameByResource(grantorResource);

      // set permissions
      Set<ResourcePermission> permissions_pre
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE),
                    ResourcePermissions.getInstance(customPermissionName));

      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName),
                 is(permissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        permissions_pre);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        grantorDomainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            grantorDomainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke global permissions as grantor and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           ResourcePermissions
                                                                 .getInstance(ResourcePermissions.IMPERSONATE));

      final Set<ResourcePermission> permissions_expected = setOf(ResourcePermissions.getInstance(customPermissionName));

      final Set<ResourcePermission> permissions_post_explicit = accessControlContext
            .getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, grantorDomainName);
      assertThat(permissions_post_explicit, is(permissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, grantorDomainName),
                 is(permissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(ResourcePermissions.IMPERSONATE)));


      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, grantorDomainName),
                 is(permissions_expected));
   }

   @Test
   public void revokeGlobalResourcePermissions_withUnauthorizedPermissionsGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String grantablePermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantablePermissionName = ResourcePermissions.IMPERSONATE;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantablePermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourcePermissions.getInstance(grantablePermissionName, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke permissions as grantor and verify
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(grantablePermissionName),
                                                              ResourcePermissions
                                                                    .getInstance(ungrantablePermissionName));
         fail("revoking existing global permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(grantablePermissionName),
                                                              ResourcePermissions
                                                                    .getInstance(ungrantablePermissionName));
         fail("revoking existing global permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions.getInstance(
                                                                          grantablePermissionName),
                                                                    ResourcePermissions
                                                                          .getInstance(ungrantablePermissionName)));
         fail("revoking existing global permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              setOf(ResourcePermissions.getInstance(
                                                                          grantablePermissionName),
                                                                    ResourcePermissions
                                                                          .getInstance(ungrantablePermissionName)));
         fail("revoking existing global permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantablePermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantablePermissionName)));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_identicalPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName1 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName2 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName3 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName4 = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre
            = setOf(ResourcePermissions.getInstance(grantedPermissionName1),
                    ResourcePermissions.getInstance(grantedPermissionName2, true),
                    ResourcePermissions.getInstance(grantedPermissionName3),
                    ResourcePermissions.getInstance(grantedPermissionName4, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(grantedPermissionName1, true),
                    ResourcePermissions.getInstance(grantedPermissionName2, true),
                    ResourcePermissions.getInstance(grantedPermissionName3, true),
                    ResourcePermissions.getInstance(grantedPermissionName4, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke permissions as grantor and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(grantedPermissionName1),
                                                           ResourcePermissions.getInstance(grantedPermissionName2, true));

      final Set<ResourcePermission> permissions_post1
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post1.size(), is(2));

      // revoke remaining permissions for implicit domain
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           ResourcePermissions.getInstance(grantedPermissionName3),
                                                           ResourcePermissions.getInstance(grantedPermissionName4, true));

      final Set<ResourcePermission> permissions_post2
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post2.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(grantedPermissionName1),
                                                                 ResourcePermissions.getInstance(grantedPermissionName2,
                                                                                                 true)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName).size(),
                 is(2));

      // test set-based version for implicit domain
      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(grantedPermissionName3),
                                                                 ResourcePermissions.getInstance(grantedPermissionName4,
                                                                                                 true)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_lesserGrantingRightPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName1 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName2 = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre
            = setOf(ResourcePermissions.getInstance(grantedPermissionName1),
                    ResourcePermissions.getInstance(grantedPermissionName2));

      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(grantedPermissionName1, true),
                    ResourcePermissions.getInstance(grantedPermissionName2, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke permissions as grantor and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(grantedPermissionName1, true));

      final Set<ResourcePermission> permissions_post1
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post1.size(), is(1));

      // revoke remaining permissions for implicit domain
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           ResourcePermissions.getInstance(grantedPermissionName2, true));

      final Set<ResourcePermission> permissions_post2
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post2.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions.getInstance(grantedPermissionName1,
                                                                                                 true)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName).size(),
                 is(1));

      // test set-based version for implicit domain
      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           setOf(ResourcePermissions.getInstance(grantedPermissionName2,
                                                                                                 true)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_greaterGrantingRightPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName1 = generateResourceClassPermission(resourceClassName);
      final String grantedPermissionName2 = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre
            = setOf(ResourcePermissions.getInstance(grantedPermissionName1, true),
                    ResourcePermissions.getInstance(grantedPermissionName2, true));

      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(grantedPermissionName1, true),
                    ResourcePermissions.getInstance(grantedPermissionName2, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke permissions as grantor and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           ResourcePermissions.getInstance(grantedPermissionName1));

      final Set<ResourcePermission> permissions_post1
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post1.size(), is(1));

      // revoke remaining permissions for implicit domain
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           ResourcePermissions.getInstance(grantedPermissionName2));

      final Set<ResourcePermission> permissions_post2
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                         resourceClassName,
                                                                         domainName);
      assertThat(permissions_post2.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           domainName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(grantedPermissionName1)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName).size(),
                 is(1));

      // test set-based version for implicit domain
      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName,
                                                           setOf(ResourcePermissions
                                                                       .getInstance(grantedPermissionName2)));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName = generateResourceClassPermission(resourceClassName);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(permissionName, true),
                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // attempt to revoke permissions with duplicate permission names
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions.getInstance(permissionName, true),
                                                              ResourcePermissions.getInstance(permissionName, false));
         fail("revoking global permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              ResourcePermissions
                                                                    .getInstance(ResourcePermissions.IMPERSONATE),
                                                              ResourcePermissions.getInstance(permissionName, true),
                                                              ResourcePermissions.getInstance(permissionName, false));
         fail("revoking global permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(ResourcePermissions.IMPERSONATE),
                                                                    ResourcePermissions.getInstance(permissionName, true),
                                                                    ResourcePermissions.getInstance(permissionName, false)));
         fail("revoking global permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              setOf(ResourcePermissions
                                                                          .getInstance(ResourcePermissions.IMPERSONATE),
                                                                    ResourcePermissions.getInstance(permissionName, true),
                                                                    ResourcePermissions.getInstance(permissionName, false)));
         fail("revoking global permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_duplicateIdenticalPermissions_shouldSucceed() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final String permissionName = generateResourceClassPermission(resourceClassName);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(permissionName, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // attempt to revoke permissions with duplicate permission names
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              ResourcePermissions.getInstance(permissionName),
                                                              ResourcePermissions.getInstance(permissionName));
         fail("revoking global resource permissions for duplicate (identical) permissions, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              ResourcePermissions.getInstance(permissionName),
                                                              ResourcePermissions.getInstance(permissionName));
         fail("revoking global resource permissions for duplicate (identical) permissions, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final String domainName = accessControlContext.getDomainNameByResource(grantorResource);
      final String domainName_whitespaced = " " + domainName + "\t";

      final String permissionName1 = generateResourceClassPermission(resourceClassName);
      final String permissionName2 = generateResourceClassPermission(resourceClassName);

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre
            = setOf(ResourcePermissions.getInstance(permissionName1),
                    ResourcePermissions.getInstance(permissionName2));

      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        domainName,
                                                        accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions
            = setOf(ResourcePermissions.getInstance(permissionName1, true),
                    ResourcePermissions.getInstance(permissionName2, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke permissions and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName_whitespaced,
                                                           domainName_whitespaced,
                                                           ResourcePermissions.getInstance(permissionName1));

      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post_specific.size(), is(1));

      // revoke permissions for implicit domain and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                           resourceClassName_whitespaced,
                                                           ResourcePermissions.getInstance(permissionName2));

      final Set<ResourcePermission> permissions_post_implicit
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName);
      assertThat(permissions_post_implicit.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName_whitespaced,
                                                           domainName_whitespaced,
                                                           ResourcePermissions.getInstance(permissionName1));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, domainName).size(),
                 is(1));

      // test set-based version for implicit domain and verify
      accessControlContext.revokeGlobalResourcePermissions(accessorResource2,
                                                           resourceClassName_whitespaced,
                                                           ResourcePermissions.getInstance(permissionName2));

      assertThat(accessControlContext
                       .getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName).isEmpty(),
                 is(true));
   }

   @Test
   public void revokeGlobalResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final ResourcePermission permission_valid = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE);

      // attempt to revoke global permissions with null references
      try {
         accessControlContext.revokeGlobalResourcePermissions(null, resourceClassName, permission_valid);
         fail("revoking permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(null, resourceClassName, domainName, permission_valid);
         fail("revoking permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource, null, permission_valid);
         fail("revoking permissions for null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource, null, domainName, permission_valid);
         fail("revoking permissions for null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              (ResourcePermission) null);
         fail("revoking permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              (ResourcePermission) null);
         fail("revoking permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             permission_valid,
                                                             null);
         fail("revoking permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             domainName,
                                                             permission_valid,
                                                             null);
         fail("revoking permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                             resourceClassName,
                                                             (String) null,
                                                             permission_valid);
         fail("revoking permissions with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(null, resourceClassName, setOf(permission_valid));
         fail("revoking permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(null, resourceClassName, domainName, setOf(permission_valid));
         fail("revoking permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource, null, setOf(permission_valid));
         fail("revoking permissions for null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource, null, domainName, setOf(permission_valid));
         fail("revoking permissions for null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              (Set<ResourcePermission>) null);
         fail("revoking permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              (Set<ResourcePermission>) null);
         fail("revoking permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              setOf(permission_valid, null));
         fail("revoking permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(permission_valid, null));
         fail("revoking permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              (String) null,
                                                              setOf(permission_valid));
         fail("revoking permissions with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // attempt to revoke global permissions with null references
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              Collections.<ResourcePermission>emptySet());
         fail("revoking permissions with null permission set should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              Collections.<ResourcePermission>emptySet());
         fail("revoking permissions with null permission set should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final ResourcePermission permission_valid
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName));

      // attempt to revoke permissions with non-existent references
      try {
         accessControlContext.revokeGlobalResourcePermissions(Resources.getInstance(-999L),
                                                              resourceClassName,
                                                              domainName,
                                                              permission_valid);
         fail("revoking permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(Resources.getInstance(-999L),
                                                              resourceClassName,
                                                              permission_valid);
         fail("revoking permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              "invalid_resourceClass",
                                                              domainName,
                                                              permission_valid);
         fail("revoking permissions with non-existent resource class reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              "invalid_resourceClass",
                                                              permission_valid);
         fail("revoking permissions with non-existent resource class reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              "invalid_domain",
                                                              permission_valid);
         fail("revoking permissions with non-existent domain reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(Resources.getInstance(-999L),
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(permission_valid));
         fail("revoking permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(Resources.getInstance(-999L),
                                                              resourceClassName,
                                                              setOf(permission_valid));
         fail("revoking permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              "invalid_resourceClass",
                                                              domainName,
                                                              setOf(permission_valid));
         fail("revoking permissions with non-existent resource class reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              "invalid_resourceClass",
                                                              setOf(permission_valid));
         fail("revoking permissions with non-existent resource class reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              "invalid_domain",
                                                              setOf(permission_valid));
         fail("revoking permissions with non-existent domain reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }

   @Test
   public void revokeGlobalResourcePermissions_mismatchedResourceClass_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      final ResourcePermission permission_valid
            = ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName));
      final ResourcePermission permission_invalid
            = ResourcePermissions.getInstance(generateResourceClassPermission(generateResourceClass(false, false)));

      // attempt to revoke permissions with mismatched resource class and permission
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              permission_valid,
                                                              permission_invalid);
         fail("revoking permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              permission_valid,
                                                              permission_invalid);
         fail("revoking permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }

      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              domainName,
                                                              setOf(permission_valid, permission_invalid));
         fail("revoking permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
      try {
         accessControlContext.revokeGlobalResourcePermissions(accessorResource,
                                                              resourceClassName,
                                                              setOf(permission_valid, permission_invalid));
         fail("revoking permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not defined for resource class"));
      }
   }
}
