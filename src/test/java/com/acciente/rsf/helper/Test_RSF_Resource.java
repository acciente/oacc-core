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
package com.acciente.rsf.helper;

import com.acciente.rsf.sql.internal.PasswordUtils;
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

public class Test_RSF_Resource {

   @Test
   public void meta_checkPasswords() {
      PasswordEncryptor oPasswordEncryptor = new StrongPasswordEncryptor();
      final String plaintext = "abc";
      final String digest_01 = oPasswordEncryptor.encryptPassword(plaintext);
      final String digest_02 = oPasswordEncryptor.encryptPassword(plaintext);
      assertThat(digest_01, is(not(digest_02)));
      assertThat(oPasswordEncryptor.checkPassword(plaintext, digest_01), is(true));
      assertThat(oPasswordEncryptor.checkPassword(plaintext, digest_02), is(true));
   }

   @Test
   public void meta_equalityOfResourcesWithEncryptedPasswords() {
      PasswordEncryptor oPasswordEncryptor = new StrongPasswordEncryptor();
      final String plaintext = "abc";
      final String digest_01 = oPasswordEncryptor.encryptPassword(PasswordUtils.computeBoundPassword(0, plaintext));
      final String digest_02 = oPasswordEncryptor.encryptPassword(PasswordUtils.computeBoundPassword(0, plaintext));

      final RSF_Resource resource_01 = new RSF_Resource.Builder(0L).resourceClassID(0L).domainID(0L).password(digest_01).build();
      final RSF_Resource resource_01_plain = new RSF_Resource.Builder(0L).resourceClassID(0L).domainID(0L).password_plaintext(plaintext).build();
      final RSF_Resource resource_02 = new RSF_Resource.Builder(0L).resourceClassID(0L).domainID(0L).password(digest_02).build();
      final RSF_Resource resource_02_plain = new RSF_Resource.Builder(0L).resourceClassID(0L).domainID(0L).password_plaintext(plaintext).build();

      assertThat(digest_01, is(not(digest_02)));
      // verify equals()
      assertThat(resource_01, is(not(resource_02)));

      assertThat(resource_01_plain, is(resource_02_plain));

      assertThat(resource_01, is(resource_01_plain));
      assertThat(resource_02, is(resource_01_plain));
      assertThat(resource_01_plain, is(resource_01));
      assertThat(resource_01_plain, is(resource_02));

      // verify hashCode()
      assertThat(resource_01_plain.hashCode(), is(resource_02_plain.hashCode()));

      assertThat(resource_01.hashCode(), is(resource_01_plain.hashCode()));
      assertThat(resource_02.hashCode(), is(resource_01_plain.hashCode()));
      assertThat(resource_01_plain.hashCode(), is(resource_01.hashCode()));
      assertThat(resource_01_plain.hashCode(), is(resource_02.hashCode()));
   }
}
