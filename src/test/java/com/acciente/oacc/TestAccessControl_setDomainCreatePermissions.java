/*
 * Copyright 2009-2018, Acciente LLC
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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_setDomainCreatePermissions extends TestAccessControlBase {
   @Test
   public void setDomainCreatePermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet<>();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void setDomainCreatePermissions_withExtId() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      final String externalId = generateUniqueExternalId();
      Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet<>();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(Resources.getInstance(externalId), domainCreatePermissions_pre);

      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void setDomainCreatePermissions_validAsAuthorized() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter = new HashSet<>();
      domainCreatePermissions_granter.add(domCreatePerm_superuser_withGrant);
      domainCreatePermissions_granter.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_granter.add(domCreatePerm_child_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(authenticatableResource, domainCreatePermissions_granter);

      Set<DomainCreatePermission> domainCreatePermissions_post;
      domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(authenticatableResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_granter));

      // now create a new resource and try to grant domainCreatePermissions as the authenticatable resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet<>();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      assertThat(domainCreatePermissions_pre, is(not(domainCreatePermissions_granter)));

      grantQueryPermission(authenticatableResource, accessorResource);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));
   }

   @Test
   public void setDomainCreatePermissions_resetPermissions() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE) ;
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      final DomainCreatePermission domCreatePerm_child_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet<>();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create);
      domainCreatePermissions_pre.add(domCreatePerm_child_withGrant);

      // initialize domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_pre));

      // reset domain create permissions and verify that only the latest apply
      Set<DomainCreatePermission> domainCreatePermissions_pre2 = new HashSet<>();
      domainCreatePermissions_pre2.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre2.add(domCreatePerm_child);

      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre2);

      final Set<DomainCreatePermission> domainCreatePermissions_post2 = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post2, is(domainCreatePermissions_pre2));

      // reset domain create permissions to empty set (i.e. remove all) and verify
      accessControlContext.setDomainCreatePermissions(accessorResource, Collections.<DomainCreatePermission>emptySet());

      final Set<DomainCreatePermission> domainCreatePermissions_post3 = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(domainCreatePermissions_post3.isEmpty(), is(true));
   }

   @Test
   public void setDomainCreatePermissions_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName)));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, requestedPermissions);

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName)));
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantedPermissionName)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }
   @Test
   public void setDomainCreatePermissions_removePermission_withUnauthorizedPermissionsGrantedElsewhere_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
            grantedPermissionName)));
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, requestedPermissions);

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantedPermissionName)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setDomainCreatePermissions_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions_pre.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, requestedPermissions);

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setDomainCreatePermissions_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions_pre.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName)));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(ungrantedPermissionName)));

      try {
         accessControlContext.setDomainCreatePermissions(accessorResource, requestedPermissions);
         fail("Downgrading (=removal of granting rights) of domain create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setDomainCreatePermissions_upgradeGrantingRightsAndPostCreateGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
            grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE));
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstanceWithGrantOption(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      grantQueryPermission(grantorResource, accessorResource);
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstanceWithGrantOption(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, requestedPermissions);

      Set<DomainCreatePermission> permissions_expected = new HashSet<>();
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      permissions_expected.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstanceWithGrantOption(grantedPermissionName)));

      final Set<DomainCreatePermission> permissions_post
            = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void setDomainCreatePermissions_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainCreatePermission> accessorPermissions_pre = new HashSet<>();
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      accessorPermissions_pre.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(
            ungrantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(accessorResource, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      grantorPermissions.add(DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // set permissions as grantor and verify
      Set<DomainCreatePermission> requestedPermissions = new HashSet<>();
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstance(grantedPermissionName)));
      requestedPermissions.add(DomainCreatePermissions.getInstance(DomainPermissions.getInstanceWithGrantOption(ungrantedPermissionName)));

      try {
         accessControlContext.setDomainCreatePermissions(accessorResource, requestedPermissions);
         fail("Upgrading (=addition of granting rights) of domain create-permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void setDomainCreatePermissions_withoutCreatePermission_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet<>();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_child);

      // attempt to set domain create permissions without passing the *CREATE system permission should fail
      try {
         accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);
         fail("setting domain create permissions without passing the *CREATE system permission should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("create must be specified"));
      }
   }

   @Test
   public void setDomainCreatePermissions_whitespaceConsistent() {
      authenticateSystemResource();

      final DomainCreatePermission domCreatePerm_superuser_trailingspaces
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER + " \t"));
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(" \t" + DomainCreatePermissions.CREATE);

      // todo: arguably, system permissions should match in name exactly, but the API uses Strings, not Enums, and is otherwise whitespace-consistent
      //       this could pose some complications depending on if the system permission name is persisted from the passed string or derived from an authoritative source
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet<>();
      domainCreatePermissions_pre.add(domCreatePerm_superuser_trailingspaces);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);

      // set domain create permissions and verify
      accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);

      final Set<DomainCreatePermission> domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(accessorResource);
      assertEquals(domainCreatePermissions_pre, domainCreatePermissions_post);
   }

   // the DomainPermission object prevents creation with invalid system permission names, hence we don't test
   // for case-sensitivity consistency of the setDomainCreatePermission() method here;
   // similarly, we currently can't set duplicate permissions because the API only allows sets of unique domain permissions,
   // hence we don't test for duplicate permissions (until the api changes, e.g. with variable argument lists instead of sets)

   @Test
   public void setDomainCreatePermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);

      Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions.add(domCreatePerm_create_withGrant);

      Set<DomainCreatePermission> domainCreatePermission_nullElement = new HashSet<>();
      domainCreatePermission_nullElement.add(null);

      Resource accessorResource = generateUnauthenticatableResource();

      // attempt to set domain create permissions with nulls
      try {
         accessControlContext.setDomainCreatePermissions(null, domainCreatePermissions);
         fail("setting domain create permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.setDomainCreatePermissions(Resources.getInstance(null), domainCreatePermissions);
         fail("setting domain create permissions with null internal/external resource ids should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.setDomainCreatePermissions(accessorResource, null);
         fail("setting domain create permissions with null domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermission_nullElement);
         fail("setting domain create permissions with null element in domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void setDomainCreatePermissions_duplicatePermissions_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup grantor permissions
      Set<DomainCreatePermission> grantorPermissions
            = setOf(DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE),
                    DomainCreatePermissions.getInstanceWithGrantOption(DomainPermissions.getInstance(grantedPermissionName)));

      accessControlContext.setDomainCreatePermissions(grantorResource, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(grantorResource), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // attempt to grant duplicate permissions and verify
      try {
         accessControlContext
               .setDomainCreatePermissions(accessorResource,
                                           setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                                 DomainCreatePermissions
                                                       .getInstance(DomainPermissions.getInstance(grantedPermissionName)),
                                                 DomainCreatePermissions
                                                       .getInstanceWithGrantOption(DomainPermissions.getInstance(grantedPermissionName))));
         fail("setting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext
               .setDomainCreatePermissions(accessorResource,
                                           setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                                 DomainCreatePermissions
                                                       .getInstance(DomainPermissions.getInstance(grantedPermissionName)),
                                                 DomainCreatePermissions
                                                       .getInstance(DomainPermissions.getInstanceWithGrantOption(grantedPermissionName))));
         fail("setting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
      try {
         accessControlContext
               .setDomainCreatePermissions(accessorResource,
                                           setOf(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE),
                                                 DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE)));
         fail("setting create permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void setDomainCreatePermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);

      Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions.add(domCreatePerm_create_withGrant);

      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      // attempt to set domain create permissions with non-existent references
      try {
         accessControlContext.setDomainCreatePermissions(invalidResource, domainCreatePermissions);
         fail("setting domain create permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setDomainCreatePermissions(invalidExternalResource, domainCreatePermissions);
         fail("setting domain create permissions with non-existent external accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }
      try {
         accessControlContext.setDomainCreatePermissions(mismatchedResource, domainCreatePermissions);
         fail("setting domain create permissions with mismatched internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }
   }

   @Test
   public void setDomainCreatePermissions_notAuthorized_shouldFail() {
      authenticateSystemResource();
      final DomainCreatePermission domCreatePerm_superuser
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      final DomainCreatePermission domCreatePerm_create
            = DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE) ;
      final DomainCreatePermission domCreatePerm_create_withGrant
            = DomainCreatePermissions.getInstanceWithGrantOption(DomainCreatePermissions.CREATE);
      final DomainCreatePermission domCreatePerm_child
            = DomainCreatePermissions.getInstance(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainCreatePermission> domainCreatePermissions_granter = new HashSet<>();
      domainCreatePermissions_granter.add(domCreatePerm_superuser);
      domainCreatePermissions_granter.add(domCreatePerm_create);

      // set domain create permissions without granting rights and verify
      accessControlContext.setDomainCreatePermissions(authenticatableResource, domainCreatePermissions_granter);

      Set<DomainCreatePermission> domainCreatePermissions_post;
      domainCreatePermissions_post = accessControlContext.getEffectiveDomainCreatePermissions(authenticatableResource);
      assertThat(domainCreatePermissions_post, is(domainCreatePermissions_granter));

      // now create a new resource and try to grant domainCreatePermissions as the authenticatable resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainCreatePermissions(accessorResource).isEmpty(), is(true));

      Set<DomainCreatePermission> domainCreatePermissions_pre = new HashSet<>();
      domainCreatePermissions_pre.add(domCreatePerm_superuser);
      domainCreatePermissions_pre.add(domCreatePerm_create_withGrant);
      domainCreatePermissions_pre.add(domCreatePerm_child);
      assertThat(domainCreatePermissions_pre, is(not(domainCreatePermissions_granter)));

      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions_pre);
         fail("setting domain create permissions without having rights to grant should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(authenticatableResource).toLowerCase()
                                                                       + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("domain create permission"));
      }
   }
}
