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

package com.acciente.oacc.encryptor.jasypt;

import org.hamcrest.core.Is;
import org.hamcrest.core.IsEqual;
import org.hamcrest.core.IsNot;
import org.junit.Test;

import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertThat;

public class JasyptPasswordEncryptorTest {
   private final JasyptPasswordEncryptor encryptor = JasyptPasswordEncryptor.getPasswordEncryptor();

   @Test
   public void encryptPasswordDifferentHashesForSamePassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass1 = encryptor.encryptPassword(testPassword);
      final String encryptedPasswordPass2 = encryptor.encryptPassword(testPassword);

      assertThat(encryptedPasswordPass1, IsNot.not(IsEqual.equalTo(encryptedPasswordPass2)));
   }

   @Test
   public void encryptPasswordHeaderMarkerPresent() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass = encryptor.encryptPassword(testPassword);

      assertThat(encryptedPasswordPass, startsWith(JasyptPasswordEncryptor.NAME + ":"));
   }

   @Test
   public void checkPassword() throws Exception {
      final char[] testPassword = "SomePasswordHere".toCharArray();

      final String encryptedPasswordPass1 = encryptor.encryptPassword(testPassword);

      assertThat(encryptor.checkPassword(testPassword, encryptedPasswordPass1), Is.is(true));
   }
}