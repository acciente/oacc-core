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

public class TestAccessControl_setResourcePermissions extends TestAccessControlBase {
   @Test
   public void setResourcePermission_validAsSystemResource() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));

      // set permissions and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void setResourcePermission_withExtId() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String accessorExternalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(accessorExternalId);
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      final String accessedExternalId2 = generateUniqueExternalId();
      final Resource accessedResource2 = accessControlContext.createResource(resourceClassName,
                                                                             generateDomain(),
                                                                             accessedExternalId2);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));

      // set permissions and verify
      accessControlContext.setResourcePermissions(Resources.getInstance(accessorExternalId), accessedResource, permissions_pre);

      Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));

      accessControlContext.setResourcePermissions(accessorResource, Resources.getInstance(accessedExternalId2), permissions_pre);

      permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource2);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void setResourcePermission_resetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));

      // attempt to set *RESET_CREDENTIALS system permission
      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);
         fail("granting *RESET_CREDENTIALS system permission to an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setResourcePermission_impersonatePermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final Resource accessedResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));

      // attempt to set *IMPERSONATE system permission
      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);
         fail("granting *IMPERSONATE system permission on an unauthenticatable resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setResourcePermission_validAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(customPermissionName));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void setResourcePermission_resetPermissions() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre1 = new HashSet<>();
      permissions_pre1.add(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT));
      permissions_pre1.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));

      // set permissions and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre1);

      final Set<ResourcePermission> permissions_post1 = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post1, is(permissions_pre1));

      // reset permissions and verify they only contain the latest
      Set<ResourcePermission> permissions_pre2 = new HashSet<>();
      permissions_pre2.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre2.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));
      assertThat(permissions_pre1, is(not(permissions_pre2)));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre2);

      final Set<ResourcePermission> permissions_post2 = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post2, is(permissions_pre2));

      // reset permissions to empty, i.e. remove all permissions
      accessControlContext.setResourcePermissions(accessorResource,
                                                  accessedResource,
                                                  Collections.<ResourcePermission>emptySet());

      final Set<ResourcePermission> permissions_post3 = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post3.isEmpty(), is(true));
   }

   @Test
   public void setResourcePermission_addPermission_withAndWithoutGrant_shouldFail() {
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
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);
         fail("setting additional permissions as grantor without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setResourcePermission_removePermission_withAndWithoutGrant_shouldFail() {
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
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));

      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);
         fail("setting fewer permissions as grantor without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setResourcePermission_addPermission_directGrant_inheritedNotSpecified_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantorPermissionName = generateResourceClassPermission(resourceClassName);
      final String donorPermissionName = generateResourceClassPermission(resourceClassName);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantorPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(donorResourcePermissions));

      // global permission
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(globalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain), is(globalResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantorPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.addAll(requestedPermissions);
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName));
      permissions_expected.addAll(globalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_removePermission_directGrant_simplified_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantorPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup direct permissions
      Set<ResourcePermission> grantorPermissions_pre = new HashSet<>();
      grantorPermissions_pre.add(ResourcePermissions.getInstance(grantorPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, grantorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(grantorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantorPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, Collections.<ResourcePermission>emptySet());

      Set<ResourcePermission> permissions_expected = Collections.emptySet();

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_removePermission_directGrant_inheritedNotSpecified_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantorPermissionName = generateResourceClassPermission(resourceClassName);
      final String donorPermissionName = generateResourceClassPermission(resourceClassName);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup direct permissions
      Set<ResourcePermission> grantorPermissions_pre = new HashSet<>();
      grantorPermissions_pre.add(ResourcePermissions.getInstance(grantorPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, grantorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(grantorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantorPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));

      // global permission
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(globalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain), is(globalResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, Collections.<ResourcePermission>emptySet());

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName));
      permissions_expected.addAll(globalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_addPermission_globalGrant_inheritedNotSpecified_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantorPermissionName = generateResourceClassPermission(resourceClassName);
      final String donorPermissionName = generateResourceClassPermission(resourceClassName);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantorPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource, resourceClassName, accessedDomain, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(donorResourcePermissions));

      // global permission
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(globalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain), is(globalResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantorPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.addAll(requestedPermissions);
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName));
      permissions_expected.addAll(globalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_removePermission_globalGrant_inheritedNotSpecified_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantorPermissionName = generateResourceClassPermission(resourceClassName);
      final String donorPermissionName = generateResourceClassPermission(resourceClassName);
      final String globalPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource donorResource = generateUnauthenticatableResource();
      final String accessedDomain = generateDomain();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, accessedDomain);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantorPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource, resourceClassName, accessedDomain, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // setup donor permissions
      Set<ResourcePermission> donorResourcePermissions = new HashSet<>();
      donorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName));

      accessControlContext.setResourcePermissions(donorResource, accessedResource, donorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(donorResource, accessedResource), is(donorResourcePermissions));

      // inherit from donor
      Set<ResourcePermission> inheritResourcePermissions = new HashSet<>();
      inheritResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, donorResource), is(inheritResourcePermissions));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(donorResourcePermissions));

      // global permission
      Set<ResourcePermission> globalResourcePermissions = new HashSet<>();
      globalResourcePermissions.add(ResourcePermissions.getInstance(globalPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain, globalResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, accessedDomain), is(globalResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, Collections.<ResourcePermission>emptySet());

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(donorPermissionName));
      permissions_expected.addAll(globalResourcePermissions);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() {
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
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(grantedPermissionName));
      permissions_expected.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_removePermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() {
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
      accessorPermissions_pre.add(ResourcePermissions.getInstance(grantedPermissionName));
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(grantedPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
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
      accessorPermissions_pre.add(ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);
         fail("Downgrading (=removal of granting rights) of permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setResourcePermission_upgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(grantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setResourcePermission_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
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
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setResourcePermissions(grantorResource, accessedResource, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource), is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName));

      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, requestedPermissions);
         fail("Upgrading (=addition of granting rights) of permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setResourcePermission_inheritanceCycle_onSelf_fromSysResource_shouldFail() {
      authenticateSystemResource();

      final String accessorDomain = generateDomain();
      final String accessorResourceClass = generateResourceClass(true, false);
      final PasswordCredentials accessorCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      final Resource accessorResource = accessControlContext.createResource(accessorResourceClass, accessorDomain, accessorCredentials);

      // attempt to grant accessor INHERIT/G on itself (so it may grant it to the accessed later)
      try {
         accessControlContext.setResourcePermissions(accessorResource,
                                                     accessorResource,
                                                     setOf(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)));
         fail("setting direct resource permission of INHERIT to itself would constitute a cycle and should not have succeeded");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("cycle"));
      }
   }

   @Test
   public void setResourcePermission_inheritanceCycle_onSelf_fromAuthResource_shouldFail() {
      // don't authenticate system resource - we're creating accessor from unauthenticated context here so
      // as to get all default (non-system) permissions

      final String accessorDomain = generateDomain();
      final String accessorResourceClass = generateResourceClass(true, true);
      final PasswordCredentials accessorCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      final Resource accessorResource = accessControlContext.createResource(accessorResourceClass, accessorDomain, accessorCredentials);

      // authenticate as accessor resource
      accessControlContext.authenticate(accessorResource, accessorCredentials);

      // attempt to grant accessor INHERIT/G on itself (so it may grant it to the accessed later)
      // NOTE: this won't work - not because of a cycle - but because currently the accessor resource
      // lacks permission to actually grant system permissions about itself, including to itself!
      try {
         accessControlContext.setResourcePermissions(accessorResource,
                                                     accessorResource,
                                                     setOf(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT)));
         fail("setting direct resource permission of INHERIT to itself should not have succeeded because accessor doesn't (and can't) have grant permission to itself");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(accessorResource).toLowerCase()
                                                                       + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("following permission"));
      }
   }

   @Test
   public void setResourcePermission_inheritanceCycle_fromAccessorAsSuperUser_shouldFail() {
      authenticateSystemResource();

      final String accessorDomain = generateDomain();
      final String accessorResourceClass = generateResourceClass(true, false);
      final PasswordCredentials accessorCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      final Resource accessorResource = accessControlContext.createResource(accessorResourceClass, accessorDomain, accessorCredentials);

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
                    ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS)));
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
         accessControlContext.setResourcePermissions(accessedResource,
                                                     accessorResource,
                                                     setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));
         fail("setting direct resource permissions that would create an inherit cycle should have failed");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("will cause a cycle"));
      }
   }

   @Test
   public void setResourcePermission_inheritanceCycle_fromPostCreateInherit_shouldFail() {
      // the test case of granting accessed --INHERIT-> accessor with accessor resource as the grantor
      // can't be produced because we can't grant *ourselves* INHERIT /G (see setResourcePermission_inheritanceCycle_onSelf_fromAuthResource_shouldFail);
      // so instead, we'll be granting accessed --INHERIT-> accessor with system resource as the grantor, again
      authenticateSystemResource();

      final String accessorDomain = generateDomain();
      final String accessorResourceClass = generateResourceClass(true, false);
      final PasswordCredentials accessorCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      final Resource accessorResource = accessControlContext.createResource(accessorResourceClass, accessorDomain, accessorCredentials);

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

      // unauthenticate (so that sys resource will attempt to grant accessed --INHERIT-> accessor)
      accessControlContext.unauthenticate();
      authenticateSystemResource();

      // attempt to grant to new resource inherit permission on accessor resource
      try {
         accessControlContext.setResourcePermissions(accessedResource,
                                                     accessorResource,
                                                     setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT)));
         fail("setting direct resource permissions that would create an inherit cycle should have failed");
      }
      catch (OaccException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("will cause a cycle"));
      }
   }

   @Test
   public void setResourcePermission_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      final String permissionName = generateResourceClassPermission(resourceClassName);
      permissions_pre.add(ResourcePermissions.getInstanceWithGrantOption(permissionName));
      permissions_pre.add(ResourcePermissions.getInstance(permissionName));

      // attempt to set permissions with duplicate permission names
      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);
         fail("setting permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void setResourcePermission_nulls_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_valid = new HashSet<>();
      permissions_valid.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      Set<ResourcePermission> permissions_nullElement = new HashSet<>();
      permissions_nullElement.add(null);

      // attempt to set permissions with null references
      try {
         accessControlContext.setResourcePermissions(null, accessedResource, permissions_valid);
         fail("setting permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.setResourcePermissions(Resources.getInstance(null), accessedResource, permissions_valid);
         fail("setting permissions for null internal/external accessor resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.setResourcePermissions(accessedResource, null, permissions_valid);
         fail("setting permissions for null accessed resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.setResourcePermissions(accessedResource, Resources.getInstance(null), permissions_valid);
         fail("setting permissions for null internal/external accessed resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.setResourcePermissions(accessedResource, accessedResource, null);
         fail("setting permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.setResourcePermissions(accessedResource, accessedResource, permissions_nullElement);
         fail("setting permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("set of permissions contains null element"));
      }
   }

   @Test
   public void setResourcePermission_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      Set<ResourcePermission> permissions_invalidName = new HashSet<>();
      permissions_invalidName.add(ResourcePermissions.getInstance("invalid_permission"));

      Set<ResourcePermission> resourcePermissions_mismatchedResourceClass = new HashSet<>();
      resourcePermissions_mismatchedResourceClass.add(ResourcePermissions.getInstance(generateResourceClassPermission(
            generateResourceClass(false, false))));

      Set<ResourcePermission> grantorPermissions
            = setOf(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstanceWithGrantOption(customPermissionName));

      // setup grantor permissions
      accessControlContext.setResourcePermissions(accessorResource, accessedResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource), is(grantorPermissions));

      Set<ResourcePermission> permissions_valid
            = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT),
                    ResourcePermissions.getInstance(customPermissionName));

      // attempt to set permissions with non-existent references
      try {
         accessControlContext.setResourcePermissions(invalidResource,
                                                     accessedResource,
                                                     permissions_valid);
         fail("setting permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setResourcePermissions(invalidExternalResource,
                                                     accessedResource,
                                                     permissions_valid);
         fail("setting permissions with non-existent external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setResourcePermissions(mismatchedResource,
                                                     accessedResource,
                                                     permissions_valid);
         fail("setting permissions with mismatched internal/external accessor resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.setResourcePermissions(accessorResource,
                                                     invalidResource,
                                                     permissions_valid);
         fail("setting permissions with non-existent accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setResourcePermissions(accessorResource,
                                                     invalidExternalResource,
                                                     permissions_valid);
         fail("setting permissions with non-existent external accessed resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setResourcePermissions(accessorResource,
                                                     mismatchedResource,
                                                     permissions_valid);
         fail("setting permissions with mismatched internal/external accessed resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.setResourcePermissions(accessorResource,
                                                     accessedResource,
                                                     resourcePermissions_mismatchedResourceClass);
         fail("setting permissions with mismatched resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }

      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_invalidName);
         fail("setting permissions with non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }

   @Test
   public void setResourcePermission_notAuthorized_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessedResource = accessControlContext.createResource(resourceClassName, generateDomain());
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessedResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      assertThat(accessControlContext.getEffectiveResourcePermissions(grantorResource, accessedResource).isEmpty(), is(true));

      // attempt to set permissions as grantor without authorization
      try {
         accessControlContext.setResourcePermissions(accessorResource, accessedResource, permissions_pre);
         fail("setting permissions as grantor without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(grantorResource).toLowerCase()
                                                                       + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("following permission"));
      }
   }
}
