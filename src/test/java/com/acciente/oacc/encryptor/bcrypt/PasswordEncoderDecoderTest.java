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

package com.acciente.oacc.encryptor.bcrypt;

import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class PasswordEncoderDecoderTest {
   private static final String MARKER    = "bcrypt:";
   private static final String BCRYPT_STRING = "$2a$12$HfshGe6U0YWGy0ylODEFx.aOIq44QupzArT1LYuAwffwLqHAhGZIW";
   private static final String ENCODED_PASSWORD = MARKER + BCRYPT_STRING;

   private final PasswordEncoderDecoder encoderDecoder = new PasswordEncoderDecoder();

   @Test
   public void encodePassword() throws Exception {
      final String encodedPassword = encoderDecoder.encode(BCRYPT_STRING);

      assertThat(encodedPassword, is(ENCODED_PASSWORD));
   }

   @Test
   public void decodePassword() throws Exception {
      final String bcryptString = encoderDecoder.decode(ENCODED_PASSWORD);

      assertThat(bcryptString, is(BCRYPT_STRING));
   }
}