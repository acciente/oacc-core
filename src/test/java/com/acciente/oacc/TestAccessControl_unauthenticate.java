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

import com.acciente.oacc.helper.Constants;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_unauthenticate extends TestAccessControlBase {
   @Test
   public void unauthenticate_authenticatedSystemUser() throws AccessControlException {
      accessControlContext.authenticate(getSystemResource(),
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));

      assertThat(accessControlContext.getAuthenticatedResource(), is(SYS_RESOURCE));
      assertThat(accessControlContext.getSessionResource(), is(SYS_RESOURCE));

      // unauthenticate and verify
      accessControlContext.unauthenticate();

      // the current contract specifies the getting authenticated or session resources should fail when unauthenticated
//      assertThat(accessControlContext.getAuthenticatedResource(), is(nullValue()));
//      assertThat(accessControlContext.getSessionResource(), is(nullValue()));
      try {
         accessControlContext.getAuthenticatedResource();
         fail("calling getAuthenticatedResource() from an unauthenticated context should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      try {
         accessControlContext.getSessionResource();
         fail("calling getSessionResource() from an unauthenticated context should have failed");
      }
      catch (AccessControlException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not authenticated"));
      }

      // check idempotency
      accessControlContext.unauthenticate();
   }
}
