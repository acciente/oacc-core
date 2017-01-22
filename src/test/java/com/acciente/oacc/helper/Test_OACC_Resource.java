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
package com.acciente.oacc.helper;

import com.acciente.oacc.Resources;
import com.acciente.oacc.sql.PasswordEncryptor;
import com.acciente.oacc.sql.internal.PasswordUtils;
import com.acciente.oacc.sql.internal.encryptor.JasyptPasswordEncryptor;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

public class Test_OACC_Resource {

   @Test
   public void meta_checkPasswords() {
      PasswordEncryptor passwordEncryptor = JasyptPasswordEncryptor.getPasswordEncryptor();
      final char[] plaintext = "abc".toCharArray();
      final String digest_01 = passwordEncryptor.encryptPassword(plaintext);
      final String digest_02 = passwordEncryptor.encryptPassword(plaintext);
      final String digest_null = passwordEncryptor.encryptPassword(null);
      assertThat(digest_01, is(not(digest_02)));
      assertThat(passwordEncryptor.checkPassword(plaintext, digest_01), is(true));
      assertThat(passwordEncryptor.checkPassword(plaintext, digest_02), is(true));
      assertThat(passwordEncryptor.checkPassword(null, digest_null), is(true));
      assertThat(passwordEncryptor.checkPassword(null, digest_01), is(false));
      assertThat(passwordEncryptor.checkPassword(plaintext, digest_null), is(false));
   }

   @Test
   public void meta_equalityOfResourcesWithEncryptedPasswords() {
      PasswordEncryptor passwordEncryptor = JasyptPasswordEncryptor.getPasswordEncryptor();
      final char[] plaintext = "abc".toCharArray();
      final String digest_01 = passwordEncryptor.encryptPassword(PasswordUtils.computeBoundPassword(
            Resources.getInstance(0), plaintext));
      final String digest_02 = passwordEncryptor.encryptPassword(PasswordUtils.computeBoundPassword(
            Resources.getInstance(0), plaintext));

      final OACC_ResourcePassword resource_01_digest = new OACC_ResourcePassword.Builder(0L).password(digest_01).build();
      final OACC_ResourcePassword resource_01_plain = new OACC_ResourcePassword.Builder(0L).password_plaintext(plaintext).build();
      final OACC_ResourcePassword resource_02_digest = new OACC_ResourcePassword.Builder(0L).password(digest_02).build();
      final OACC_ResourcePassword resource_02_plain = new OACC_ResourcePassword.Builder(0L).password_plaintext(plaintext).build();

      assertThat(digest_01, is(not(digest_02)));
      // verify equals()
      assertThat(resource_01_digest, is(not(resource_02_digest)));

      assertThat(resource_01_plain, is(resource_02_plain));

      assertThat(resource_01_digest, is(resource_01_plain));
      assertThat(resource_02_digest, is(resource_01_plain));
      assertThat(resource_01_plain, is(resource_01_digest));
      assertThat(resource_01_plain, is(resource_02_digest));

      // verify hashCode()
      assertThat(resource_01_plain.hashCode(), is(resource_02_plain.hashCode()));

      assertThat(resource_01_digest.hashCode(), is(resource_01_plain.hashCode()));
      assertThat(resource_02_digest.hashCode(), is(resource_01_plain.hashCode()));
      assertThat(resource_01_plain.hashCode(), is(resource_01_digest.hashCode()));
      assertThat(resource_01_plain.hashCode(), is(resource_02_digest.hashCode()));
   }
}
