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

package com.acciente.oacc.encryptor;

import com.acciente.oacc.encryptor.bcrypt.BCryptPasswordEncryptor;
import com.acciente.oacc.encryptor.jasypt.JasyptPasswordEncryptor;
import com.acciente.oacc.encryptor.jasypt.LegacyJasyptPasswordEncryptor;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class TransitioningPasswordEncryptorTest {
   private final LegacyJasyptPasswordEncryptor  legacyEncryptor        = LegacyJasyptPasswordEncryptor.newInstance();
   private final BCryptPasswordEncryptor        bcryptEncryptor        = BCryptPasswordEncryptor.newInstance(4);
   private final TransitioningPasswordEncryptor transitioningEncryptor = TransitioningPasswordEncryptor.newInstance(bcryptEncryptor, legacyEncryptor);

   @Test
   public void encryptNullPassword() throws Exception {
      final char[] testPassword = null;

      final String encryptedPassword = transitioningEncryptor.encryptPassword(testPassword);

      assertThat(encryptedPassword, is(nullValue()));
   }

   @Test
   public void checkNullPasswords() throws Exception {
      final char[] testPassword = null;

      final String encryptedPassword = transitioningEncryptor.encryptPassword(testPassword);

      assertThat(transitioningEncryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkNullLegacyPasswords() throws Exception {
      final char[] testPassword = null;

      final String encryptedPassword = legacyEncryptor.encryptPassword(testPassword);

      assertThat(transitioningEncryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkNullPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPassword = transitioningEncryptor.encryptPassword(testPassword);

      assertThat(transitioningEncryptor.checkPassword(null, encryptedPassword), is(false));
   }

   @Test
   public void checkNullLegacyPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPassword = legacyEncryptor.encryptPassword(testPassword);

      assertThat(transitioningEncryptor.checkPassword(null, encryptedPassword), is(false));
   }

   @Test
   public void checkNullStoredPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      assertThat(transitioningEncryptor.checkPassword(testPassword, null), is(false));
   }

   @Test
   public void checkPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPassword = transitioningEncryptor.encryptPassword(testPassword);

      assertThat(transitioningEncryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkLegacyPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPassword = legacyEncryptor.encryptPassword(testPassword);

      assertThat(transitioningEncryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkBcryptPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPassword = bcryptEncryptor.encryptPassword(testPassword);

      assertThat(transitioningEncryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkPostTransitionBcryptPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPassword = transitioningEncryptor.encryptPassword(testPassword);

      assertThat(bcryptEncryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkNormalizedLegacyPassword() throws Exception {
      final char[] combiningSequencePwd = new char[]{'A', 0x30a}; // A, combining-ring-above
      final char[] singleCharacterPwd = new char[]{0x00c5};       // latin-capital-a-with-ring-above (Å)

      final String encryptedPassword = legacyEncryptor.encryptPassword(combiningSequencePwd);

      assertThat(transitioningEncryptor.checkPassword(singleCharacterPwd, encryptedPassword), is(true));
   }

   @Test
   public void checkChainedLegacyPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();
      final JasyptPasswordEncryptor jasyptEncryptor = JasyptPasswordEncryptor.newInstance("SHA-256", 100000, 16);
      final TransitioningPasswordEncryptor legacy2JasyptEncryptor = TransitioningPasswordEncryptor.newInstance(jasyptEncryptor, legacyEncryptor);
      final TransitioningPasswordEncryptor legacy2Jasypt2BcryptEncryptor = TransitioningPasswordEncryptor.newInstance(bcryptEncryptor, legacy2JasyptEncryptor);

      final String encryptedPassword = legacyEncryptor.encryptPassword(testPassword);

      assertThat(legacy2Jasypt2BcryptEncryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }

   @Test
   public void checkChainedIntermediatePassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();
      final JasyptPasswordEncryptor jasyptEncryptor = JasyptPasswordEncryptor.newInstance("SHA-256", 100000, 16);
      final TransitioningPasswordEncryptor legacy2JasyptEncryptor = TransitioningPasswordEncryptor.newInstance(jasyptEncryptor, legacyEncryptor);
      final TransitioningPasswordEncryptor legacy2Jasypt2BcryptEncryptor = TransitioningPasswordEncryptor.newInstance(bcryptEncryptor, legacy2JasyptEncryptor);

      final String encryptedPassword = legacy2JasyptEncryptor.encryptPassword(testPassword);

      assertThat(legacy2Jasypt2BcryptEncryptor.checkPassword(testPassword, encryptedPassword), is(true));
   }
}