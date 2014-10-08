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
package com.acciente.rsf;

import org.junit.Test;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestAccessControl_getEffectiveDomainPermissions extends TestAccessControlBase {
   @Test
   public void getEffectiveDomainPermissions_emptyAsSystemResource() throws AccessControlException {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<DomainPermission> domainPermissions = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainPermissions_emptyAsAuthenticated() throws AccessControlException {
      final Resource accessorResource = generateUnauthenticatableResource();

      generateResourceAndAuthenticate();

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      final String domainName = generateDomain();
      final Set<DomainPermission> domainPermissions = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions.isEmpty(), is(true));
   }

   @Test
   public void getEffectiveDomainPermissions_validAsSystemResource() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermission.getInstance(DomainPermission.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN);
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN, true);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domCreatePerm_superuser);
      domainPermissions_pre1.add(domCreatePerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      final Set<DomainPermission> domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName1);
      assertThat(domainPermissions_post, is(domainPermissions_pre1));

      // let's try another domain
      Set<DomainPermission> domainPermissions_pre2 = new HashSet<>();
      domainPermissions_pre2.add(domCreatePerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions2 = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      final Set<DomainPermission> domainPermissions_post2 = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName2);
      assertThat(domainPermissions_post2, is(domainPermissions_pre2));
   }

   @Test
   public void getEffectiveDomainPermissions_validWithInheritFromParentDomain() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermission.getInstance(DomainPermission.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermission.getInstance(DomainPermission.SUPER_USER, true);
      final DomainPermission domPerm_createchilddomain
            = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN, true);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = new HashSet<>();
      parentDomainPermissions_pre.add(domPerm_superuser_withGrant);
      parentDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = new HashSet<>();
      childDomainPermissions_pre.add(domPerm_superuser);
      childDomainPermissions_pre.add(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // verify
      Set<DomainPermission> childDomainPermissions_expected = new HashSet<>();
      childDomainPermissions_expected.addAll(parentDomainPermissions_pre);
      childDomainPermissions_expected.addAll(childDomainPermissions_pre);

      final Set<DomainPermission> childDomainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, childDomain);
      assertThat(childDomainPermissions_post, is(childDomainPermissions_expected));

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(2));
      assertThat(allDomainPermissions.get(parentDomain), is(parentDomainPermissions_pre));
      assertThat(allDomainPermissions.get(childDomain), is(childDomainPermissions_expected));
   }

   @Test
   public void getEffectiveDomainPermissions_validWithInheritFromAncestorDomainWithEmptyIntermediaryAncestors() throws AccessControlException {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermission.getInstance(DomainPermission.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermission.getInstance(DomainPermission.SUPER_USER, true);
      final DomainPermission domPerm_createchilddomain
            = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN, true);

      final String parentDomain = generateDomain();
      final String childDomain = generateUniqueDomainName();
      final String grandChildDomain = generateUniqueDomainName();
      final String greatGrandChildDomain = generateUniqueDomainName();
      final String greatGreatGrandChildDomain = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain, parentDomain);
      accessControlContext.createDomain(grandChildDomain, childDomain);
      accessControlContext.createDomain(greatGrandChildDomain, grandChildDomain);
      accessControlContext.createDomain(greatGreatGrandChildDomain, greatGrandChildDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = new HashSet<>();
      parentDomainPermissions_pre.add(domPerm_superuser_withGrant);
      parentDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = new HashSet<>();
      childDomainPermissions_pre.add(domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // set great-great-grand-child domain permissions
      Set<DomainPermission> greatGreatGrandChildDomainPermissions_pre = new HashSet<>();
      greatGreatGrandChildDomainPermissions_pre.add(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource,
                                                greatGreatGrandChildDomain,
                                                greatGreatGrandChildDomainPermissions_pre);

      // verify
      Set<DomainPermission> childDomainPermissions_expected = new HashSet<>();
      childDomainPermissions_expected.addAll(parentDomainPermissions_pre);
      childDomainPermissions_expected.addAll(childDomainPermissions_pre);

      Set<DomainPermission> grandChildDomainPermissions_expected = new HashSet<>();
      grandChildDomainPermissions_expected.addAll(parentDomainPermissions_pre);
      grandChildDomainPermissions_expected.addAll(childDomainPermissions_pre);

      Set<DomainPermission> greatGrandChildDomainPermissions_expected = new HashSet<>();
      greatGrandChildDomainPermissions_expected.addAll(parentDomainPermissions_pre);
      greatGrandChildDomainPermissions_expected.addAll(childDomainPermissions_pre);

      Set<DomainPermission> greatGreatGrandChildDomainPermissions_expected = new HashSet<>();
      greatGreatGrandChildDomainPermissions_expected.addAll(parentDomainPermissions_pre);
      greatGreatGrandChildDomainPermissions_expected.addAll(childDomainPermissions_pre);
      greatGreatGrandChildDomainPermissions_expected.addAll(greatGreatGrandChildDomainPermissions_pre);

      final Set<DomainPermission> greatGreatGrandChildDomainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, greatGreatGrandChildDomain);
      assertThat(greatGreatGrandChildDomainPermissions_post, is(greatGreatGrandChildDomainPermissions_expected));

      final Map<String,Set<DomainPermission>> allDomainPermissions = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(5));
      assertThat(allDomainPermissions.get(parentDomain), is(parentDomainPermissions_pre));
      assertThat(allDomainPermissions.get(childDomain), is(childDomainPermissions_expected));
      assertThat(allDomainPermissions.get(grandChildDomain), is(grandChildDomainPermissions_expected));
      assertThat(allDomainPermissions.get(greatGrandChildDomain), is(greatGrandChildDomainPermissions_expected));
      assertThat(allDomainPermissions.get(greatGreatGrandChildDomain), is(greatGreatGrandChildDomainPermissions_expected));
   }

   @Test
   public void getEffectiveDomainPermissions_nulls_shouldFail() throws AccessControlException {
      authenticateSystemResource();

      try {
         accessControlContext.getEffectiveDomainPermissionsMap(null);
      }
      catch (NullPointerException e) {
      }

      try {
         accessControlContext.getEffectiveDomainPermissions(null, generateDomain());
      }
      catch (NullPointerException e) {
      }

      try {
         accessControlContext.getEffectiveDomainPermissions(generateUnauthenticatableResource(), null);
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain name must not be null"));
      }
   }
}
