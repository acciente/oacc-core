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

package com.acciente.oacc.encryptor.jasypt;

import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertThat;

public class JasyptPasswordEncryptorTest {
   private final JasyptPasswordEncryptor encryptor = JasyptPasswordEncryptor.newInstance("SHA-256", 100000, 16);

   @Test
   public void encryptNullPassword() throws Exception {
      final char[] testPassword = null;

      final String encryptedPassword = encryptor.encryptPassword(testPassword);

      assertThat(encryptedPassword, is(nullValue()));
   }

   @Test
   public void encryptPasswordDifferentHashesForSamePassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass1 = encryptor.encryptPassword(testPassword);
      final String encryptedPasswordPass2 = encryptor.encryptPassword(testPassword);

      assertThat(encryptedPasswordPass1, not(equalTo(encryptedPasswordPass2)));
   }

   @Test
   public void encryptPasswordHeaderMarkerPresent() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass = encryptor.encryptPassword(testPassword);

      assertThat(encryptedPasswordPass, startsWith(JasyptPasswordEncryptor.NAME + ":"));
   }

   @Test
   public void checkNullPasswords() throws Exception {
      final char[] testPassword = null;

      final String encryptedPassword = encryptor.encryptPassword(testPassword);

      assertThat(encryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkNullPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPassword = encryptor.encryptPassword(testPassword);

      assertThat(encryptor.checkPassword(null, encryptedPassword), is(false));
   }

   @Test
   public void checkNullStoredPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      assertThat(encryptor.checkPassword(testPassword, null), is(false));
   }

   @Test
   public void checkPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass1 = encryptor.encryptPassword(testPassword);

      assertThat(encryptor.checkPassword(testPassword, encryptedPasswordPass1), is(true));
   }

   @Test
   public void checkNormalizedPassword() throws Exception {
      final char[] combiningSequencePwd = new char[]{'A', 0x30a}; // A, combining-ring-above
      final char[] singleCharacterPwd = new char[]{0x00c5};       // latin-capital-a-with-ring-above (Å)

      final String encryptedPasswordPass1 = encryptor.encryptPassword(combiningSequencePwd);

      assertThat(encryptor.checkPassword(singleCharacterPwd, encryptedPasswordPass1), is(true));
   }
}