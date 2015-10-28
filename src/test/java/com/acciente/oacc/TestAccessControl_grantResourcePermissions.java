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

public class TestAccessControl_grantResourcePermissions extends TestAccessControlBase {
   @Test
   public void grantResourcePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // grant permissions and verify
      accessControlContext.grantResourcePermissions(accessorResource,
                                                    accessedResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                    ResourcePermissions.getInstance(customPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));

      // test set-based version
      final Resource accessedResource2 = accessControlContext.createResource(resourceClassName, generateDomain());

      accessControlContext.grantResourcePermissions(accessorResource,
                                                    accessedResource2,
                                                    setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                          ResourcePermissions.getInstance(customPermissionName)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource2),
                 is(permissions_pre));
   }

   @Test
   public void grantResourcePermissions_withExtId() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final String accessorExternalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(accessorExternalId);
      final String accessedExternalId = generateUniqueExternalId();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName,
                                                                            generateDomain(),
                                                                            accessedExternalId);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // grant permissions and verify
      accessControlContext.grantResourcePermissions(Resources.getInstance(accessorExternalId),
                                                    accessedResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                    ResourcePermissions.getInstance(customPermissionName));

      Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));

      final String accessorExternalId2 = generateUniqueExternalId();
      final Resource accessorResource2 = generateUnauthenticatableResourceWithExtId(accessorExternalId2);
      accessControlContext.grantResourcePermissions(accessorResource2,
                                                    Resources.getInstance(accessedExternalId),
                                                    ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                    ResourcePermissions.getInstance(customPermissionName));

      permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource);
      assertThat(permissions_post, is(permissions_pre));

      // test set-based version
      final String accessedExternalId2 = generateUniqueExternalId();
      final Resource accessedResource2 = accessControlContext.createResource(resourceClassName,
                                                                             generateDomain(),
                                                                             accessedExternalId2);

      accessControlContext.grantResourcePermissions(Resources.getInstance(accessorExternalId),
                                                    accessedResource2,
                                                    setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                          ResourcePermissions.getInstance(customPermissionName)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource2),
                 is(permissions_pre));

      accessControlContext.grantResourcePermissions(accessorResource2,
                                                    Resources.getInstance(accessedExternalId2),
                                                    setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                          ResourcePermissions.getInstance(customPermissionName)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource2),
                 is(permissions_pre));
   }

   @Test
   public void grantResourcePermissions_resetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // attempt to grant *RESET_CREDENTIALS system permission
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));
         fail("granting *RESET_CREDENTIALS system permission to an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
         fail("granting *RESET_CREDENTIALS system permission to an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void grantResourcePermissions_impersonatePermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // attempt to grant *IMPERSONATE system permission
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions
                                                             .getInstance(ResourcePermissions.IMPERSONATE));
         fail("granting *IMPERSONATE system permission on an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE)));
         fail("granting *IMPERSONATE system permission on an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void grantResourcePermissions_validAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      // setup grantor permissions
      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(
            grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantResourcePermissions(accessorResource,
                                                    accessedResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                    ResourcePermissions.getInstance(customPermissionName));

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_expected.add(ResourcePermissions.getInstance(customPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      grantQueryPermission(grantorResource, accessorResource2);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource).isEmpty(), is(true));

      accessControlContext.grantResourcePermissions(accessorResource2,
                                                    accessedResource,
                                                    setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                          ResourcePermissions.getInstance(customPermissionName)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource),
                 is(permissions_expected));
   }

   @Test
   public void grantResourcePermissions_addPermissions() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));
      grantorResourcePermissions.add(ResourcePermissions.getInstance(customPermissionName, true));

      // setup grantor permissions
      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(
            grantorResourcePermissions));

      // setup accessor permissions
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource),
                 is(setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT))));

      accessControlContext.setResourcePermissions(accessorResource2,
                                                  accessedResource,
                                                  setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));
      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantResourcePermissions(accessorResource,
                                                    accessedResource,
                                                    ResourcePermissions.getInstance(customPermissionName));

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_expected.add(ResourcePermissions.getInstance(customPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource),
                 is(setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT))));

      accessControlContext.grantResourcePermissions(accessorResource2,
                                                    accessedResource,
                                                    setOf(ResourcePermissions.getInstance(customPermissionName)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource),
                 is(permissions_expected));
   }

   @Test
   public void grantResourcePermissions_addPermission_withAndWithoutGrant_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(
            grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(grantedPermissionName),
                                                       ResourcePermissions.getInstance(ungrantedPermissionName));
         fail("granting additional permissions as grantor without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions.getInstance(grantedPermissionName),
                                                             ResourcePermissions.getInstance(ungrantedPermissionName)));
         fail("granting additional permissions as grantor without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantResourcePermissions_addPermission_directGrant_inheritedNotSpecified_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantorPermissionName = generateResourceClassPermission(resourceClassName);
      final String donorPermissionName = generateResourceClassPermission(resourceClassName);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(grantorPermissionName, true));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstance(donorPermissionName, true));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(donorResourcePermissions));

      accessControlContext.setResourcePermissions(accessorResource2, donorResource, inheritResourcePermissions);

      // global permission
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(globalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessedDomain,
                                                        globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            accessedDomain), is(
            globalResourcePermissions));

      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        accessedDomain,
                                                        globalResourcePermissions);

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantResourcePermissions(accessorResource,
                                                    accessedResource,
                                                    ResourcePermissions.getInstance(grantorPermissionName));

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(grantorPermissionName));
      permissions_expected.add(ResourcePermissions.getInstance(donorPermissionName, true));
      permissions_expected.addAll(globalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, donorResource), is( inheritResourcePermissions));
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, accessedDomain),
                 is(globalResourcePermissions));

      accessControlContext.grantResourcePermissions(accessorResource2,
                                                    accessedResource,
                                                    setOf(ResourcePermissions.getInstance(grantorPermissionName)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource),
                 is(permissions_expected));
   }

   @Test
   public void grantResourcePermissions_addPermission_globalGrant_inheritedNotSpecified_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantorPermissionName = generateResourceClassPermission(resourceClassName);
      final String donorPermissionName = generateResourceClassPermission(resourceClassName);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(grantorPermissionName, true));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        accessedDomain,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstance(donorPermissionName, true));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(
            inheritResourcePermissions));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(donorResourcePermissions));

      accessControlContext.setResourcePermissions(accessorResource2, donorResource, inheritResourcePermissions);

      // global permission
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(globalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        accessedDomain,
                                                        globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource,
                                                                            resourceClassName,
                                                                            accessedDomain), is(
            globalResourcePermissions));

      accessControlContext.setGlobalResourcePermissions(accessorResource2,
                                                        resourceClassName,
                                                        accessedDomain,
                                                        globalResourcePermissions);

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantResourcePermissions(accessorResource,
                                                    accessedResource,
                                                    ResourcePermissions.getInstance(grantorPermissionName));

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(grantorPermissionName));
      permissions_expected.add(ResourcePermissions.getInstance(donorPermissionName, true));
      permissions_expected.addAll(globalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, donorResource),
                 is(inheritResourcePermissions));
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource2, resourceClassName, accessedDomain),
                 is(globalResourcePermissions));

      accessControlContext.grantResourcePermissions(accessorResource2,
                                                    accessedResource,
                                                    setOf(ResourcePermissions.getInstance(grantorPermissionName)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource), is(permissions_expected));
   }

   @Test
   public void grantResourcePermissions_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldFailAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(grantedPermissionName),
                                                       ResourcePermissions.getInstance(ungrantedPermissionName));
         fail("granting existing permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions.getInstance(grantedPermissionName),
                                                             ResourcePermissions.getInstance(ungrantedPermissionName)));
         fail("granting existing permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantResourcePermissions_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(
            accessorPermissions_pre));

      accessControlContext.setResourcePermissions(accessorResource2, accessedResource, accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(
            grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantResourcePermissions(accessorResource,
                                                    accessedResource,
                                                    ResourcePermissions.getInstance(grantedPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(grantorResourcePermissions));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource),
                 is(accessorPermissions_pre));

      accessControlContext.grantResourcePermissions(accessorResource2,
                                                    accessedResource,
                                                    setOf(ResourcePermissions.getInstance(grantedPermissionName)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource),
                 is(grantorResourcePermissions));
   }

   @Test
   public void grantResourcePermissions_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantedPermissionName, true));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(grantedPermissionName),
                                                       ResourcePermissions.getInstance(ungrantedPermissionName));
         fail("Downgrading (=removal of granting rights) of permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions.getInstance(grantedPermissionName),
                                                             ResourcePermissions.getInstance(ungrantedPermissionName)));
         fail("Downgrading (=removal of granting rights) of permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantResourcePermissions_upgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(grantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(
            accessorPermissions_pre));

      accessControlContext.setResourcePermissions(accessorResource2, accessedResource, accessorPermissions_pre);

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(
            grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      grantQueryPermission(grantorResource, accessorResource2);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantResourcePermissions(accessorResource,
                                                    accessedResource,
                                                    ResourcePermissions.getInstance(grantedPermissionName, true));

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(grantedPermissionName, true));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));

      // test set-based version
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource), is(
            accessorPermissions_pre));

      accessControlContext.grantResourcePermissions(accessorResource2,
                                                    accessedResource,
                                                    setOf(ResourcePermissions.getInstance(grantedPermissionName, true)));

      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource2, accessedResource),
                 is(permissions_expected));
   }

   @Test
   public void grantResourcePermissions_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.INHERIT;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(grantedPermissionName),
                                                       ResourcePermissions.getInstance(ungrantedPermissionName));
         fail("Upgrading (=addition of granting rights) of permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions.getInstance(grantedPermissionName),
                                                             ResourcePermissions.getInstance(ungrantedPermissionName)));
         fail("Upgrading (=addition of granting rights) of permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantResourcePermissions_inheritanceCycle_onSelf_fromSysResource_shouldFail() {
      authenticateSystemResource();

      final String accessorDomain = generateDomain();
      final String accessorResourceClass = generateResourceClass(true, false);
      final PasswordCredentials accessorCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      final Resource accessorResource = accessControlContext.createResource(accessorResourceClass, accessorDomain, accessorCredentials);

      // attempt to grant accessor INHERIT/G on itself
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessorResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));
         fail("granting direct resource permission of INHERIT to itself would constitute a cycle and should not have succeeded");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cycle"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessorResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT, true)));
         fail("granting direct resource permission of INHERIT to itself would constitute a cycle and should not have succeeded");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cycle"));
      }
   }

   @Test
   public void grantResourcePermissions_inheritanceCycle_onSelf_fromAuthResource_shouldFail() {
      // don't authenticate system resource - we're creating accessor from unauthenticated context here so
      // as to get all default (non-system) permissions

      final String accessorDomain = generateDomain();
      final String accessorResourceClass = generateResourceClass(true, true);
      final PasswordCredentials accessorCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      final Resource accessorResource = accessControlContext.createResource(accessorResourceClass,
                                                                            accessorDomain,
                                                                            accessorCredentials);

      // authenticate as accessor resource
      accessControlContext.authenticate(accessorResource, accessorCredentials);

      // attempt to grant accessor INHERIT/G on itself
      // NOTE: this won't work - not because of a cycle - but because currently the accessor resource
      // lacks permission to actually grant system permissions about itself, including to itself!
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessorResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true));
         fail("granting direct resource permission of INHERIT to itself should not have succeeded because accessor doesn't (and can't) have grant permission to itself");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessorResource).toLowerCase()
                                                                       + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("following permission"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessorResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT, true)));
         fail("granting direct resource permission of INHERIT to itself should not have succeeded because accessor doesn't (and can't) have grant permission to itself");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessorResource).toLowerCase()
                                                                       + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("following permission"));
      }
   }

   @Test
   public void grantResourcePermissions_inheritanceCycle_fromAccessorAsSuperUser_shouldFail() {
      authenticateSystemResource();

      final String accessorDomain = generateDomain();
      final String accessorResourceClass = generateResourceClass(true, false);
      final PasswordCredentials accessorCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      final Resource accessorResource = accessControlContext.createResource(accessorResourceClass,
                                                                            accessorDomain,
                                                                            accessorCredentials);

      final String accessedDomain = generateDomain();
      final String accessedResourceClass = generateResourceClass(true, false);

      // set up accessor resource as a super user on the accessor domain (so we can later grant accessed permission on ourselves)
      accessControlContext.setDomainPermissions(accessorResource,
                                                accessorDomain,
                                                setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));

      accessControlContext.assertDomainPermissions(accessorResource,
                                                   accessorDomain,
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER));

      // grant resource create permissions to accessor resource, including INHERIT post-create permission
      final Set<ResourceCreatePermission> resourceCreatePermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions
                                                                .getInstance(ResourcePermissions.RESET_CREDENTIALS)));
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        accessedResourceClass,
                                                        accessedDomain,
                                                        resourceCreatePermissions);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               accessedResourceClass,
                                                               accessedDomain,
                                                               ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      // authenticate as accessor resource
      accessControlContext.authenticate(accessorResource, accessorCredentials);

      // create resource
      final Resource accessedResource = accessControlContext.createResource(accessedResourceClass,
                                                                            accessedDomain,
                                                                            PasswordCredentials.newInstance(generateUniquePassword()));

      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      // attempt to grant to new resource inherit permission on accessor resource
      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessorResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("granting direct resource permissions that would create an inherit cycle should have failed");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("will cause a cycle"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessorResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)));
         fail("granting direct resource permissions that would create an inherit cycle should have failed");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("will cause a cycle"));
      }
   }

   @Test
   public void grantResourcePermissions_inheritanceCycle_fromPostCreateInherit_shouldFail() {
      // the test case of granting accessed --INHERIT-> accessor with accessor resource as the grantor
      // can't be produced because we can't grant *ourselves* INHERIT /G (see grantResourcePermissions_inheritanceCycle_onSelf_fromAuthResource_shouldFail);
      // so instead, we'll be granting accessed --INHERIT-> accessor with system resource as the grantor, again
      authenticateSystemResource();

      final String accessorDomain = generateDomain();
      final String accessorResourceClass = generateResourceClass(true, false);
      final PasswordCredentials accessorCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      final Resource accessorResource = accessControlContext.createResource(accessorResourceClass,
                                                                            accessorDomain,
                                                                            accessorCredentials);

      final String accessedDomain = generateDomain();
      final String accessedResourceClass = generateResourceClass(true, false);

      // grant resource create permissions to accessor resource, including INHERIT post-create permission
      final Set<ResourceCreatePermission> resourceCreatePermissions
            = setOf(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)),
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS)));
      accessControlContext.setResourceCreatePermissions(accessorResource,
                                                        accessedResourceClass,
                                                        accessedDomain,
                                                        resourceCreatePermissions);

      accessControlContext.assertPostCreateResourcePermissions(accessorResource,
                                                               accessedResourceClass,
                                                               accessedDomain,
                                                               ResourcePermissions
                                                                     .getInstance(ResourcePermissions.INHERIT));

      // authenticate as accessor resource
      accessControlContext.authenticate(accessorResource, accessorCredentials);

      // create resource
      final Resource accessedResource = accessControlContext.createResource(accessedResourceClass,
                                                                            accessedDomain,
                                                                            PasswordCredentials.newInstance(generateUniquePassword()));

      accessControlContext.assertResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      // unauthenticate (so that sys resource will attempt to grant accessed --INHERIT-> accessor)
      accessControlContext.unauthenticate();
      authenticateSystemResource();

      // attempt to grant to new resource inherit permission on accessor resource
      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessorResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("granting direct resource permissions that would create an inherit cycle should have failed");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("will cause a cycle"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessorResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)));
         fail("granting direct resource permissions that would create an inherit cycle should have failed");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("will cause a cycle"));
      }
   }

   @Test
   public void grantResourcePermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      final String permissionName = generateResourceClassPermission(resourceClassName);

      // attempt to grant permissions with duplicate permission names
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions.getInstance(permissionName, true),
                                                       ResourcePermissions.getInstance(permissionName, false));
         fail("granting permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             ResourcePermissions.getInstance(permissionName, true),
                                                             ResourcePermissions.getInstance(permissionName, false)));
         fail("granting permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void grantResourcePermissions_duplicateIdenticalPermissions_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      final String permissionName = generateResourceClassPermission(resourceClassName);

      // attempt to grant permissions with duplicate permission names
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(permissionName),
                                                       ResourcePermissions.getInstance(permissionName));
         fail("granting resource permissions with duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void grantResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // attempt to grant permissions with null references
      try {
         accessControlContext.grantResourcePermissions(null,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("granting permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantResourcePermissions(Resources.getInstance(null),
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("granting permissions for null internal/external accessor resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       null,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("granting permissions for null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       Resources.getInstance(null),
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
         fail("granting permissions for null internal/external accessed resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessedResource,
                                                       (ResourcePermission) null);
         fail("granting permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       null);
         fail("granting permissions with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.grantResourcePermissions(null,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)));
         fail("granting permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantResourcePermissions(Resources.getInstance(null),
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)));
         fail("granting permissions for null internal/external accessor resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       null,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)));
         fail("granting permissions for null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       Resources.getInstance(null),
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT)));
         fail("granting permissions for null internal/external accessed resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessedResource,
                                                       (Set<ResourcePermission>) null);
         fail("granting permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             null));
         fail("granting permissions with null permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void grantResourcePermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // attempt to grant permissions with null references
      try {
         accessControlContext.grantResourcePermissions(accessedResource,
                                                       accessedResource,
                                                       Collections.<ResourcePermission>emptySet());
         fail("granting permissions with null permission set should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void grantResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      Set<ResourcePermission> grantorPermissions
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true),
                    ResourcePermissions.getInstance(customPermissionName, true));

      // setup grantor permissions
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(grantorPermissions));

      // attempt to grant permissions with non-existent references
      try {
         accessControlContext.grantResourcePermissions(invalidResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions.getInstance(customPermissionName));
         fail("granting permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourcePermissions(invalidExternalResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions.getInstance(customPermissionName));
         fail("granting permissions with non-existent external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourcePermissions(mismatchedResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions.getInstance(customPermissionName));
         fail("granting permissions with mismatched internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       invalidResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions.getInstance(customPermissionName));
         fail("granting permissions with non-existent accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       invalidExternalResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions.getInstance(customPermissionName));
         fail("granting permissions with non-existent external accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       mismatchedResource,
                                                       ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                                                       ResourcePermissions.getInstance(customPermissionName));
         fail("granting permissions with mismatched internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions
                                                             .getInstance(generateResourceClassPermission(
                                                                   generateResourceClass(false, false))));
         fail("granting permissions with mismatched resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       ResourcePermissions.getInstance("invalid_permission"));
         fail("granting permissions with non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.grantResourcePermissions(invalidResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             ResourcePermissions.getInstance(customPermissionName)));
         fail("granting permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourcePermissions(invalidExternalResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             ResourcePermissions.getInstance(customPermissionName)));
         fail("granting permissions with non-existent external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourcePermissions(mismatchedResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             ResourcePermissions.getInstance(customPermissionName)));
         fail("granting permissions with mismatched internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       invalidResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             ResourcePermissions.getInstance(customPermissionName)));
         fail("granting permissions with non-existent accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       invalidExternalResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             ResourcePermissions.getInstance(customPermissionName)));
         fail("granting permissions with non-existent external accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       mismatchedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(ResourcePermissions.INHERIT),
                                                             ResourcePermissions.getInstance(customPermissionName)));
         fail("granting permissions with mismatched internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions
                                                                   .getInstance(generateResourceClassPermission(
                                                                         generateResourceClass(false, false)))));
         fail("granting permissions with mismatched resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.grantResourcePermissions(accessorResource,
                                                       accessedResource,
                                                       setOf(ResourcePermissions.getInstance("invalid_permission")));
         fail("granting permissions with non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }
}
