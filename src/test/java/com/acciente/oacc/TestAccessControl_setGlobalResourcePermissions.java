/*
 * Copyright 2009-2017, Acciente LLC
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
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_setGlobalResourcePermissions extends TestAccessControlBase {
   @Test
   public void setGlobalResourcePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // create dummy domain and class - to check if there were any side-effects later on
      generateDomain();
      generateResourceClass(true, false);

      // set permissions and verify
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(
            authenticatableResourceClassName)));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        authenticatableResourceClassName,
                                                        domainName,
                                                        permissions_pre);

      final Set<ResourcePermission> permissions_post_specific = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, domainName);
      assertThat(permissions_post_specific, is(permissions_pre));

      // verify no other global permissions were set (i.e. no side-effects)
      final Map<String, Map<String, Set<ResourcePermission>>> permissions_post_all = accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource);
      assertThat(permissions_post_all.size(), is(1));
      assertThat(permissions_post_all.get(domainName).size(), is(1));
      assertThat(permissions_post_all.get(domainName).get(authenticatableResourceClassName), is(permissions_pre));

      assertThat(accessControlContext.getEffectiveResourceCreatePermissionsMap(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, accessorResource).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveResourcePermissions(accessorResource, SYS_RESOURCE).isEmpty(), is(true));
   }

   @Test
   public void setGlobalResourcePermissions_withExtId() {
      authenticateSystemResource();
      final String authenticatableResourceClassName = generateResourceClass(true, false);
      final String externalId = generateUniqueExternalId();
      final Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // create dummy domain and class - to check if there were any side-effects later on
      generateDomain();
      generateResourceClass(true, false);

      // set permissions and verify
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(
            authenticatableResourceClassName)));

      accessControlContext.setGlobalResourcePermissions(Resources.getInstance(externalId),
                                                        authenticatableResourceClassName,
                                                        domainName,
                                                        permissions_pre);

      final Set<ResourcePermission> permissions_post_specific = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, authenticatableResourceClassName, domainName);
      assertThat(permissions_post_specific, is(permissions_pre));
   }

   @Test
   public void setGlobalResourcePermissions_inheritSystemPermission_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));

      // attempt to set *INHERIT system permission
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           permissions_pre);
         fail("setting *INHERIT system permission as a global permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid in this context"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_resetCredentialsPermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS));

      // attempt to set *RESET_CREDENTIALS system permission
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           permissions_pre);
         fail("granting *RESET_CREDENTIALS system permission globally to an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_impersonatePermissionOnUnauthenticatables_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));

      // attempt to set *IMPERSONATE system permission
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           permissions_pre);
         fail("granting *IMPERSONATE system permission globally to an unauthenticatable resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not valid for unauthenticatable resource"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_validAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE));
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(customPermissionName));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // setup grantor permissions
      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName), is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set global permissions as grantor and verify
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        permissions_pre);

      final Set<ResourcePermission> permissions_post = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_pre));
   }

   @Test
   public void setGlobalResourcePermissions_resetPermissions() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre1 = new HashSet<>();
      permissions_pre1.add(ResourcePermissions.getInstanceWithGrantOption(ResourcePermissions.IMPERSONATE));
      permissions_pre1.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));

      // set permissions and verify
      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName,
                                                        domainName,
                                                        permissions_pre1);

      final Set<ResourcePermission> permissions_post1 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post1, is(permissions_pre1));

      // reset permissions and verify they only contain the latest
      Set<ResourcePermission> permissions_pre2 = new HashSet<>();
      permissions_pre2.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre2.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName)));
      assertThat(permissions_pre1, is(not(permissions_pre2)));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        permissions_pre2);

      final Set<ResourcePermission> permissions_post2 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post2, is(permissions_pre2));

      // reset permissions to empty, i.e. remove all permissions
      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        Collections.<ResourcePermission>emptySet());

      final Set<ResourcePermission> permissions_post3 = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post3.isEmpty(), is(true));
   }

   @Test
   public void setGlobalResourcePermissions_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.IMPERSONATE;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(grantedPermissionName));
      permissions_expected.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setGlobalResourcePermissions_removePermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.IMPERSONATE;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(grantedPermissionName));
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorPermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName,
                                                                            domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setGlobalResourcePermissions_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource,
                                                        resourceClassName,
                                                        domainName,
                                                        grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource,
                                                                            resourceClassName,
                                                                            domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstance(grantedPermissionName));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setGlobalResourcePermissions_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.IMPERSONATE;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource, resourceClassName, domainName, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);
         fail("Downgrading (=removal of granting rights) of global permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setGlobalResourcePermissions_upgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(false, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource, resourceClassName, domainName, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);

      Set<ResourcePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      final Set<ResourcePermission> permissions_post
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setGlobalResourcePermissions_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String grantedPermissionName = generateResourceClassPermission(resourceClassName);
      final String ungrantedPermissionName = ResourcePermissions.IMPERSONATE;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<ResourcePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(ResourcePermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName),
                 is(accessorPermissions_pre));

      // setup grantor permissions
      Set<ResourcePermission> grantorResourcePermissions = new HashSet<>();
      grantorResourcePermissions.add(ResourcePermissions.getInstanceWithGrantOption(grantedPermissionName));

      accessControlContext.setGlobalResourcePermissions(grantorResource, resourceClassName, domainName, grantorResourcePermissions);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissions(grantorResource, resourceClassName, domainName),
                 is(grantorResourcePermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<ResourcePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(ResourcePermissions.getInstance(grantedPermissionName));
      requestedPermissions.add(ResourcePermissions.getInstanceWithGrantOption(ungrantedPermissionName));

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, requestedPermissions);
         fail("Upgrading (=addition of granting rights) of global permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setGlobalResourcePermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      final String permissionName = generateResourceClassPermission(resourceClassName);
      permissions_pre.add(ResourcePermissions.getInstanceWithGrantOption(permissionName));
      permissions_pre.add(ResourcePermissions.getInstance(permissionName));

      // attempt to set permissions with duplicate permission names
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           permissions_pre);
         fail("setting global permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String resourceClassName_whitespaced = " " + resourceClassName + "\t";
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      final String domainName_whitespaced = " " + domainName + "\t";
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      // set permissions and verify
      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(
            resourceClassName)));

      accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                        resourceClassName_whitespaced,
                                                        domainName_whitespaced,
                                                        permissions_pre);

      final Set<ResourcePermission> permissions_post_specific
            = accessControlContext.getEffectiveGlobalResourcePermissions(accessorResource, resourceClassName, domainName);
      assertThat(permissions_post_specific, is(permissions_pre));
   }

   @Test
   public void setGlobalResourcePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_valid = new HashSet<>();
      permissions_valid.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      Set<ResourcePermission> permissions_nullElement = new HashSet<>();
      permissions_nullElement.add(null);

      // attempt to set global permissions with null references
      try {
         accessControlContext.setGlobalResourcePermissions(null, resourceClassName, domainName, permissions_valid);
         fail("setting permissions for null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.setGlobalResourcePermissions(Resources.getInstance(null), resourceClassName, domainName, permissions_valid);
         fail("setting permissions for null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, null, domainName, permissions_valid);
         fail("setting permissions for null resource class name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource class required"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, domainName, null);
         fail("setting permissions with null permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           permissions_nullElement);
         fail("setting permissions with null permission should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("set of permissions contains null element"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource, resourceClassName, null, permissions_valid);
         fail("setting permissions with null domain should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_mismatchedResourceClassAndPermission_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName1 = generateResourceClass(true, false);
      final String resourceClassName2 = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(generateResourceClassPermission(resourceClassName1)));

      // attempt to set global permissions for mismatched resource class and permission
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName2,
                                                           domainName,
                                                           permissions_pre);
         fail("setting global permissions with mismatched resource class and permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      Set<ResourcePermission> permissions_invalidName = new HashSet<>();
      permissions_invalidName.add(ResourcePermissions.getInstance("invalid_permission"));

      Set<ResourcePermission> resourcePermissions_invalidResourceClass = new HashSet<>();
      resourcePermissions_invalidResourceClass.add(ResourcePermissions.getInstance(generateResourceClassPermission(
            resourceClassName)));

      // attempt to set permissions with non-existent references
      try {
         accessControlContext.setGlobalResourcePermissions(invalidResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourcePermissions_invalidResourceClass);
         fail("setting permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setGlobalResourcePermissions(invalidExternalResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourcePermissions_invalidResourceClass);
         fail("setting permissions with non-existent external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setGlobalResourcePermissions(mismatchedResource,
                                                           resourceClassName,
                                                           domainName,
                                                           resourcePermissions_invalidResourceClass);
         fail("setting permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           "invalid_resourceClass",
                                                           domainName,
                                                           resourcePermissions_invalidResourceClass);
         fail("setting permissions with non-existent resource class should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find resource class"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           "invalid_domain",
                                                           permissions_invalidName);
         fail("setting permissions with non-existent domain should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           permissions_invalidName);
         fail("setting permissions with non-existent permission name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not defined for resource class"));
      }
   }

   @Test
   public void setGlobalResourcePermissions_notAuthorized_shouldFail() {
      authenticateSystemResource();
      final String resourceClassName = generateResourceClass(true, false);
      final String customPermissionName = generateResourceClassPermission(resourceClassName);
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = accessControlContext.getDomainNameByResource(accessorResource);
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(accessorResource).isEmpty(), is(true));

      Set<ResourcePermission> permissions_pre = new HashSet<>();
      permissions_pre.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      permissions_pre.add(ResourcePermissions.getInstance(customPermissionName));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));
      assertThat(accessControlContext.getEffectiveGlobalResourcePermissionsMap(grantorResource).isEmpty(), is(true));

      // attempt to set permissions as grantor without authorization
      try {
         accessControlContext.setGlobalResourcePermissions(accessorResource,
                                                           resourceClassName,
                                                           domainName,
                                                           permissions_pre);
         fail("setting global permissions as grantor without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(grantorResource).toLowerCase()
                                                                       + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("global permission"));
      }
   }
}
