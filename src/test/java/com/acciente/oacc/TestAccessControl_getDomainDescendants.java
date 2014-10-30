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
package com.acciente.oacc;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_getDomainDescendants extends TestAccessControlBase {
   @Test
   public void getDomainDescendents_nonExistingDomain() throws AccessControlException {
      authenticateSystemResource();

      // because we don't have a getter for *all* domains, I'm using unique domain name for each test run
      assertThat(accessControlContext.getDomainDescendants(generateUniqueDomainName()).isEmpty(), is(true));
   }

   @Test
   public void getDomainDescendents_nulls() throws AccessControlException {
      authenticateSystemResource();

      try {
         accessControlContext.getDomainDescendants(null);
         fail("getting domain descendents' names with null domain name should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }
   }

   // todo: still need to test: sysdomain, leaf domain, non-leaf domain
}
